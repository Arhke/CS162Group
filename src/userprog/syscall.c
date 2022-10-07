#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"


#define validate_space(if_, ptr, n) ({                                                                          \
    if ((void *) ((char *) ptr + n) > PHYS_BASE ||                                                              \
            !(pagedir_get_page(active_pd(), ptr) && pagedir_get_page(active_pd(), (char *) ptr + n - 1))) {     \
        process_exit(-1);                                                                                       \
        return;                                                                                                 \
    }                                                                                                           \
})

#define validate_string(if_, str) ({                                                                            \
    uint32_t *pd = active_pd();                                                                                 \
    if (pagedir_get_page(pd, str) == NULL) {                                                                    \
        process_exit(-1);                                                                                       \
        return;                                                                                                 \
    }                                                                                                           \
    char *cptr = (char *) str;                                                                                  \
    while ((void *) cptr < PHYS_BASE && pagedir_get_page(pd, cptr) && *(cptr++));                                                                                                                                       \
    if (pagedir_get_page(pd, cptr) == NULL) {                                                                   \
        process_exit(-1);                                                                                       \
        return;                                                                                                 \
    }                                                                                                           \
})


static struct lock fs_lock; /* Global file syscall lock */

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    lock_init(&fs_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f) {
    uint32_t* args = ((uint32_t*)f->esp);
    validate_space(f, args, sizeof(uint32_t));

    /*
    * The following print statement, if uncommented, will print out the syscall
    * number whenever a process enters a system call. You might find it useful
    * when debugging. It will cause tests to fail, however, so you should not
    * include it in your final submission.
    */

    // printf("Process %s executing system call number: %d\n", thread_current()->pcb->process_name, args[0]);

    switch (args[0]) {
        case SYS_PRACTICE:
            validate_space(f, args, 2 * sizeof(uint32_t));

            f->eax = args[1] + 1;
            break;
        case SYS_HALT:
            shutdown_power_off();
            break;
        case SYS_EXIT:
            validate_space(f, args, 2 * sizeof(uint32_t));

            f->eax = args[1];
            process_exit(args[1]);
            break;
        case SYS_EXEC:
            validate_space(f, args, 2 * sizeof(uint32_t));
            char *file_name = (char *) args[1];
            validate_string(f, file_name);

            pid_t pid = process_execute((char *) args[1]);
            if (pid == TID_ERROR) {
                f->eax = -1;
            } else {
                f->eax = pid;
            }
            break;
        case SYS_WAIT:
            validate_space(f, args, 2 * sizeof(uint32_t));

            f->eax = process_wait(args[1]);
            break;
        case SYS_WRITE:
            validate_space(f, args, 3 * sizeof(uint32_t));
            int fd = args[1];
            char* buff_ptr = (char *) args[2];
            size_t buff_size = args[3];
            validate_string(f, buff_ptr);

            if (fd == 1) {
                lock_acquire(&fs_lock);
                    putbuf(buff_ptr, buff_size);
                lock_release(&fs_lock);
            }
            break;
    }
}
