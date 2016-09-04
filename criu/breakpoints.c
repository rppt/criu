#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "asm/types.h"
#include "ptrace.h"
#include "parasite-syscall.h"

int breakpoints_inject(pid_t pid)
{
	return 0;
}

int breakpoints_remove(pid_t pid)
{
	return 0;
}

int breakpoints_init(const char *breakpoints_file)
{
	return 0;
}
