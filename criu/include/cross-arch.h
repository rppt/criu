#ifndef __CR_CROSS_ARCH_H__
#define __CR_CROSS_ARCH_H__

extern int cross_arch_prepare_core(CoreEntry *core);
extern void cross_arch_thread_info_free(CoreEntry *core);

/* from arch/xxx/crtools.c */
extern int arch_alloc_thread_info(CoreEntry *core);

#endif /* __CR_CROSS_ARCH_H__ */
