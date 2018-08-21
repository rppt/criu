#include <sys/types.h>
#include <linux/auxvec.h>
#include <unistd.h>

#include "asm/types.h"

#include "images/core.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "images/mm.pb-c.h"

#include "int.h"
#include "cr_options.h"
#include "log.h"
#include "xmalloc.h"
#include "cross-arch.h"
#include "proc_parse.h"

#include "stack_transform.h"

static const char *arch_name[] = {
	[CORE_ENTRY__MARCH__UNKNOWN]	= "UNKNOWN",
	[CORE_ENTRY__MARCH__X86_64]	= "X86_64",
	[CORE_ENTRY__MARCH__ARM]	= "ARM",
	[CORE_ENTRY__MARCH__AARCH64]	= "AARCH64",
	[CORE_ENTRY__MARCH__PPC64]	= "PPC64",
};

void cross_arch_thread_info_free(CoreEntry *core)
{
	xfree(CORE_THREAD_ARCH_INFO(core));
	CORE_THREAD_ARCH_INFO(core) = NULL;
}

int cross_arch_prepare_core(CoreEntry *core)
{
	if (!opts.cross_arch)
		return 0;

	pr_info("Starting cross-ISA restore from %s to %s\n", arch_name[core->mtype], arch_name[CORE_ENTRY__MARCH]);

	if (arch_alloc_thread_info(core))
		return -1;

	if (!CORE_THREAD_ARCH_INFO(core))
		return -1;

	core_force_native(core);

	return 0;
}

static auxv_t mm_saved_auxv[AT_VECTOR_SIZE];
static int mm_saved_auxv_len;

int cross_arch_init(void)
{
	if (!opts.cross_arch)
		return 0;

	mm_saved_auxv_len = read_task_auxv(getpid(), mm_saved_auxv,
					   sizeof(mm_saved_auxv));
	if (mm_saved_auxv_len < 0)
		return -1;

	return 0;
}

static auxv_t auxv_ent[] = {
	AT_PHDR,
	AT_PHENT,
	AT_PHNUM,
	AT_BASE,
	AT_ENTRY,
	AT_EXECFN,
};

static bool should_adjust_auxv(auxv_t ent)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(auxv_ent); i++)
		if (auxv_ent[i] == ent)
			return true;

	return false;
}

static void adjust_auxv(MmEntry *mm, auxv_t ent, auxv_t val)
{
	int i;

	for (i = 0; i < mm->n_mm_saved_auxv; i += 2) {
		if (mm->mm_saved_auxv[i] == ent) {
			mm->mm_saved_auxv[i + 1] = val;
			break;
		}
	}
}

void cross_arch_adjust_mm_entry(MmEntry *mm)
{
	int i;

	if (!opts.cross_arch)
		return;

	for (i = 0; i < AT_VECTOR_SIZE; i += 2) {
		if (should_adjust_auxv(mm->mm_saved_auxv[i]))
			adjust_auxv(mm, i, mm_saved_auxv[i + 1]);
	}

	mm->n_mm_saved_auxv = AT_VECTOR_SIZE;
}
