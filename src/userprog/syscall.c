#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"


#define validate_ptr(ptr) ({                                                                        \
    if ((void *) ptr < 0 || (void *) ptr >= PHYS_BASE) {                                        \
        return;                                                                                     \
    }                                                                                               \
})

static struct lock fs_lock; /* Global file syscall lock */

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
    lock_init(&fs_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame* f UNUSED) {
    uint32_t* args = ((uint32_t*)f->esp);

    /*
    * The following print statement, if uncommented, will print out the syscall
    * number whenever a process enters a system call. You might find it useful
    * when debugging. It will cause tests to fail, however, so you should not
    * include it in your final submission.
    */

    /* printf("System call number: %d\n", args[0]); */

    switch (args[0]) {
        case SYS_PRACTICE:
            f->eax = args[1] + 1;
            break;
        case SYS_HALT:
            shutdown_power_off();
            break;
        case SYS_EXIT:
            f->eax = args[1];
            process_exit(args[1]);
            break;
        case SYS_EXEC: ;
            char *file_name = (char *) args[1];
            // validate_ptr(file_name);
            // validate_ptr(file_name + strlen(file_name));
            pid_t pid = process_execute((char *) args[1]);
            if (pid == TID_ERROR) {
                f->eax = -1;
            } else {
                f->eax = pid;
            }
            break;
        case SYS_WAIT:
            f->eax = process_wait(args[1]);
            break;
        case SYS_WRITE: ;
            int fd = args[1];
            char* buff_ptr = (char *) args[2];
            size_t buff_size = args[3];
            // validate_ptr(buff_ptr);
            lock_acquire(&fs_lock);
            if (fd == 1) {
                putbuf(buff_ptr, buff_size);
            }
            lock_release(&fs_lock);
            break;
    }
}
