#ifndef __BREAKPOINTS_H
#define __BREAKPOINTS_H

extern int breakpoints_init(const char *breakpoints_file);
extern int breakpoints_inject(pid_t pid);
extern int breakpoints_remove(pid_t pid);
extern int breakpoints_reset_ip(pid_t pid);
extern void *breakpoint_code(void);

#endif /* __BREAKPOINTS_H */
