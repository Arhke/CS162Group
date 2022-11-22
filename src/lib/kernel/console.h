#ifndef __LIB_KERNEL_CONSOLE_H
#define __LIB_KERNEL_CONSOLE_H

void console_init(void);
void console_panic(void);
void console_print_stats(void);

void acquire_console(void);
void release_console(void);

#endif /* lib/kernel/console.h */
