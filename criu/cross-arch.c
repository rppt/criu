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
#include "vma.h"
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

static st_handle st_xform_src, st_xform_dst;

struct xform_ops {
	void (*regs2xform)(CoreEntry *core, void *xform_regs);
	void (*xform2regs)(CoreEntry *core, void *xform_regs);
	uint64_t (*get_sp)(CoreEntry *core);
	uint64_t (*tid_addr)(CoreEntry *core);
};

static void regs2xform_aarch64(CoreEntry *core, void *xform_regs)
{
	UserAarch64RegsEntry *gpregs = core->ti_aarch64->gpregs;
	struct regset_aarch64 *regset = xform_regs;
	int i;

	for (i = 0; i < 31; i++)
		regset->x[i] = gpregs->regs[i];
	regset->sp = (void *)gpregs->sp;
	regset->pc = (void *)gpregs->pc;
}

static void xform2regs_aarch64(CoreEntry *core, void *xform_regs)
{
	UserAarch64RegsEntry *gpregs = core->ti_aarch64->gpregs;
	struct regset_aarch64 *regset = xform_regs;
	int i;

	for (i = 0; i < 31; i++)
		gpregs->regs[i] = regset->x[i];
	gpregs->sp = (uint64_t)regset->sp;
	gpregs->pc = (uint64_t)regset->pc;
}

static uint64_t get_sp_aarch64(CoreEntry *core)
{
	UserAarch64RegsEntry *gpregs = core->ti_aarch64->gpregs;

	return gpregs->sp;
}

static uint64_t tid_addr_aarch64(CoreEntry *core)
{
	return core->ti_aarch64->clear_tid_addr;
}

static void regs2xform_x86(CoreEntry *core, void *xform_regs)
{
	UserX86RegsEntry *gpregs = core->thread_info->gpregs;
	struct regset_x86_64 *regset = xform_regs;

	regset->rax = gpregs->ax;
	regset->rbx = gpregs->bx;
	regset->rcx = gpregs->cx;
	regset->rdx = gpregs->dx;
	regset->rsi = gpregs->si;
	regset->rdi = gpregs->di;
	regset->rbp = gpregs->bp;
	regset->rsp = gpregs->sp;
	regset->r8 = gpregs->r8;
	regset->r9 = gpregs->r9;
	regset->r10 = gpregs->r10;
	regset->r11 = gpregs->r11;
	regset->r12 = gpregs->r12;
	regset->r13 = gpregs->r13;
	regset->r14 = gpregs->r14;
	regset->r15 = gpregs->r15;

	regset->cs = gpregs->cs;
	regset->ds = gpregs->ds;
	regset->es = gpregs->es;
	regset->fs = gpregs->fs;
	regset->gs = gpregs->gs;
	regset->ss = gpregs->ss;

	regset->rflags = gpregs->flags;
	regset->rip = (void *)gpregs->ip;
}

static void xform2regs_x86(CoreEntry *core, void *xform_regs)
{
	UserX86RegsEntry *gpregs = core->thread_info->gpregs;
	struct regset_x86_64 *regset = xform_regs;

	gpregs->ax = regset->rax;
	gpregs->bx = regset->rbx;
	gpregs->cx = regset->rcx;
	gpregs->dx = regset->rdx;
	gpregs->si = regset->rsi;
	gpregs->di = regset->rdi;
	gpregs->bp = regset->rbp;
	gpregs->sp = regset->rsp;
	gpregs->r8 = regset->r8;
	gpregs->r9 = regset->r9;
	gpregs->r10 = regset->r10;
	gpregs->r11 = regset->r11;
	gpregs->r12 = regset->r12;
	gpregs->r13 = regset->r13;
	gpregs->r14 = regset->r14;
	gpregs->r15 = regset->r15;

	gpregs->cs = regset->cs;
	gpregs->ds = regset->ds;
	gpregs->es = regset->es;
	gpregs->fs = regset->fs;
	gpregs->gs = regset->gs;
	gpregs->ss = regset->ss;

	regset->rflags = gpregs->flags;
	gpregs->ip = (uint64_t)regset->rip;

	gpregs->orig_ax = gpregs->ax;

#if defined(__x86_64) || defined(__x86_64__)
	{
		unsigned int sel;
		asm("movl %%cs,%0" : "=r" (sel));
		gpregs->cs = sel;
		asm("movl %%ds,%0" : "=r" (sel));
		gpregs->ds = sel;
		asm("movl %%es,%0" : "=r" (sel));
		gpregs->es = sel;
		asm("movl %%ss,%0" : "=r" (sel));
		gpregs->ss = sel;
	}
#endif

/* FIXME: */
/* typedef struct { */
/* 	uint64_t	flags; */
/* 	uint64_t	fs_base; */
/* 	uint64_t	gs_base; */
/* 	uint64_t	fs; */
/* 	uint64_t	gs; */
/* } user_regs_struct64; */

}

static uint64_t get_sp_x86(CoreEntry *core)
{
	UserX86RegsEntry *gpregs = core->thread_info->gpregs;

	return gpregs->sp;
}

static uint64_t tid_addr_x86(CoreEntry *core)
{
	return core->thread_info->clear_tid_addr;
}

static const struct xform_ops xform_ops[] = {
	[CORE_ENTRY__MARCH__X86_64]	= {
		.regs2xform	= regs2xform_x86,
		.xform2regs	= xform2regs_x86,
		.get_sp		= get_sp_x86,
		.tid_addr	= tid_addr_x86,
	},
	[CORE_ENTRY__MARCH__AARCH64]	= {
		.regs2xform	= regs2xform_aarch64,
		.xform2regs	= xform2regs_aarch64,
		.get_sp		= get_sp_aarch64,
		.tid_addr	= tid_addr_aarch64,
	},
};

static int xform_stack(CoreEntry *core, uint64_t top, uint64_t bottom,
		       void *old_stack, void *new_stack)
{
	uint64_t src_regs[128] = { 0 };
	uint64_t dst_regs[128] = { 0 };
	void *src_sp_base, *dst_sp_base;

	src_sp_base = old_stack + (bottom - top);
	dst_sp_base = new_stack + (bottom - top);

	xform_ops[core->mtype].regs2xform(core, src_regs);

	if (st_rewrite_relocated_stack(st_xform_src, src_regs,
				       src_sp_base, (void *)bottom,
				       st_xform_dst, dst_regs,
				       dst_sp_base, (void *)bottom))
		return -1;

	xform_ops[CORE_ENTRY__MARCH].xform2regs(core, dst_regs);

	return 0;
}

int cross_arch_stack_xform(CoreEntry *core, MmEntry *mm,
			   struct vm_area_list *vmas)
{
	uint64_t sp, top = 0, bot = 0, start_stack, len;
	void *stack, *buf;
	struct vma_area *vma;
	int ret;

	if (!opts.cross_arch)
		return 0;

	sp = xform_ops[core->mtype].get_sp(core);
	start_stack = mm->mm_start_stack;

	list_for_each_entry_reverse(vma, &vmas->h, list) {
		if (sp >= vma->e->start  && sp < vma->e->end) {
			top = vma->e->start;
			bot = vma->e->end;
			break;
		}
	}

	if (!top || !bot)
		return -1;

	stack = (void *)vma->premmaped_addr;
	len = bot - top;

	buf = xzalloc(len);
	if (!buf)
		return -1;

	memcpy(buf, stack, len);

	if (start_stack >= top && start_stack < bot) {
		pr_debug("top: %lx, bot: %lx, start: %lx\n",
			top, bot, start_stack);
		bot = start_stack;
	}

	ret = xform_stack(core, top, bot, buf, stack);
	xfree(buf);

	CORE_THREAD_ARCH_INFO(core)->clear_tid_addr = xform_ops[core->mtype].tid_addr(core);

	return ret;
}

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

	st_xform_src = st_init(opts.cross_arch_src);
	if (!st_xform_src)
		return -1;

	st_xform_dst = st_init(opts.cross_arch_dst);
	if (!st_xform_dst)
		goto free_st_src;

	mm_saved_auxv_len = read_task_auxv(getpid(), mm_saved_auxv,
					   sizeof(mm_saved_auxv));
	if (mm_saved_auxv_len < 0)
		goto free_st_dst;

	return 0;

free_st_dst:
	st_destroy(st_xform_dst);
free_st_src:
	st_destroy(st_xform_src);
	return -1;
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
