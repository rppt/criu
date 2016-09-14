#include "asm/types.h"

#include "cr_options.h"
#include "log.h"
#include "xmalloc.h"
#include "cross-arch.h"

#include "images/core.pb-c.h"

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

	core->mtype = CORE_ENTRY__MARCH;
	if (arch_alloc_thread_info(core))
		return -1;

	if (!CORE_THREAD_ARCH_INFO(core))
		return -1;

	core_force_native(core);

	return 0;
}
