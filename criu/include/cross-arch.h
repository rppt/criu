#ifndef __CR_CROSS_ARCH_H__
#define __CR_CROSS_ARCH_H__

extern int cross_arch_init(void);
extern int cross_arch_prepare_core(CoreEntry *core);
extern void cross_arch_thread_info_free(CoreEntry *core);
extern void cross_arch_adjust_mm_entry(MmEntry *mm);
extern int cross_arch_stack_xform(CoreEntry *core, MmEntry *mm,
				  struct vm_area_list *vmas);

/* from arch/xxx/crtools.c */
extern int arch_alloc_thread_info(CoreEntry *core);

#endif /* __CR_CROSS_ARCH_H__ */
