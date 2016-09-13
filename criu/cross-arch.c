#include "cr_options.h"
#include "log.h"

#include "asm/types.h"

#include "images/core.pb-c.h"

static const char *arch_name[] = {
	[CORE_ENTRY__MARCH__UNKNOWN]	= "UNKNOWN",
	[CORE_ENTRY__MARCH__X86_64]	= "X86_64",
	[CORE_ENTRY__MARCH__ARM]	= "ARM",
	[CORE_ENTRY__MARCH__AARCH64]	= "AARCH64",
	[CORE_ENTRY__MARCH__PPC64]	= "PPC64",
};

int cross_arch_prepare_core(CoreEntry *core)
{
	if (!opts.cross_arch)
		return 0;

	pr_info("Starting cross-ISA restore from %s to %s\n", arch_name[core->mtype], arch_name[CORE_ENTRY__MARCH]);

	core->mtype = CORE_ENTRY__MARCH;

	return 0;
}
