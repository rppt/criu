#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "asm/types.h"
#include "ptrace.h"
#include "xmalloc.h"
#include "util.h"
#include "parasite-syscall.h"
#include "breakpoints.h"

struct breakpoint {
	void *addr;
	u8 code_orig[BUILTIN_SYSCALL_SIZE];
};

static struct breakpoint *breakpoints;
static int nr_breakpoints;

int breakpoints_inject(pid_t pid)
{
	return 0;
}

int breakpoints_remove(pid_t pid)
{
	return 0;
}

static int breakpoints_parse(char *mem, size_t len)
{
	int bp_num = 0;
	long addr;
	char *endp;

	while (len) {
		addr = strtoul(mem, &endp, 0);

		if (*endp != '\n') {
			if (len > 1)
				*(endp + 1) = '\0';
			else
				*endp = '\0';
			pr_err("Unparsable breakpoint: %s (%p - %p %ld)\n", mem, mem, endp, len);
			return -1;
		}

		if (bp_num >= nr_breakpoints - 1) {
			int nr_realloc = nr_breakpoints + (nr_breakpoints + 1) / 2;
			breakpoints = xrealloc(breakpoints,
					       nr_realloc * sizeof(*breakpoints));
			if (!breakpoints) {
				pr_perror("Out of memory\n");
				return -1;
			}
			nr_breakpoints += nr_realloc;
		}

		breakpoints[bp_num].addr = (void *)addr;
		memzero(&breakpoints[bp_num].code_orig, BUILTIN_SYSCALL_SIZE);
		bp_num++;
		len -= (endp - mem + 1);
		mem = endp + 1;
	}

	nr_breakpoints = bp_num;
	return 0;
}

int breakpoints_init(const char *breakpoints_file)
{
	void *mem = MAP_FAILED;
	int fd = -1, ret = -1;
	struct stat st;

	fd = open(breakpoints_file, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s\n", breakpoints_file);
		return -1;
	}

	if (fstat(fd, &st)) {
		pr_perror("Can't stat file %s\n", breakpoints_file);
		goto close_fd;
	}

	/* let's presume breakpoing address is ~8 bytes */
	nr_breakpoints = st.st_size / 8;
	breakpoints = xzalloc(sizeof(*breakpoints) * nr_breakpoints);
	if (!breakpoints) {
		pr_perror("Can't allocate memory\n");
		goto close_fd;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap file %s\n", breakpoints_file);
		goto free_bpts;
	}

	if (breakpoints_parse(mem, st.st_size)) {
		pr_err("Failed to parse file `%s'\n", breakpoints_file);
		goto unmap;
	}

	ret = 0;
	goto unmap;

free_bpts:
	xfree(breakpoints);
unmap:
	munmap(mem, st.st_size);
close_fd:
	close_safe(&fd);
	return ret;
}
