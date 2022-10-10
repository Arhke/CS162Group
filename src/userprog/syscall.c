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
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/float.h"


#define validate_space(if_, ptr, n) ({                                                                          \
    if ((void *) ((char *) ptr + n) > PHYS_BASE ||                                                              \
            !(pagedir_get_page(active_pd(), ptr) && pagedir_get_page(active_pd(), (char *) ptr + n - 1))) {     \
        process_exit(-1);                                                                                       \
        return;                                                                                                 \
    }                                                                                                           \
})

#define validate_string(if_, str) ({                                                                            \
    uint32_t *pd = active_pd();                                                                                 \
    if ((void *) str >= PHYS_BASE || pagedir_get_page(pd, str) == NULL) {                                       \
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

    char* file_name;
    struct file* desc;
    int fd;
    struct process* pcb;
    unsigned buff_size;
    char* buff_ptr;

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
            lock_acquire(&fs_lock);
            validate_space(f, args, 2 * sizeof(uint32_t));
            file_name = (char *) args[1];
            validate_string(f, file_name);

            pid_t pid = process_execute((char *) args[1]);
            if (pid == TID_ERROR) {
                f->eax = -1;
            } else {
                f->eax = pid;
            }
            lock_release(&fs_lock);
            break;
        case SYS_WAIT:
            validate_space(f, args, 2 * sizeof(uint32_t));

            f->eax = process_wait(args[1]);
            break;
        case SYS_CREATE:
            validate_space(f, args, sizeof(uint32_t) + sizeof(char *) + sizeof(unsigned));
            file_name = (char *) args[1];
            validate_string(f, file_name);
            int32_t initial_size = args[2];

            lock_acquire(&fs_lock);
                f->eax = filesys_create(file_name, initial_size);
            lock_release(&fs_lock);

            break;
        case SYS_REMOVE:
            validate_space(f, args, sizeof(uint32_t) + sizeof(char *));
            file_name = (char *) args[1];
            validate_string(f, file_name);

            lock_acquire(&fs_lock);
                f->eax = filesys_remove(file_name);
            lock_release(&fs_lock);

            break;
        case SYS_OPEN:
            validate_space(f, args, sizeof(uint32_t) + sizeof(char *));
            file_name = (char *) args[1];
            validate_string(f, file_name);

            lock_acquire(&fs_lock);
                pcb = thread_current()->pcb;
                fd = open_fd(pcb);
                desc = filesys_open(file_name);

                if (fd == -1 || desc == NULL) {
                    f->eax = -1;
                } else {
                    pcb->fdt[fd] = desc;
                    f->eax = fd;
                }
            lock_release(&fs_lock);
                
            break;
        case SYS_FILESIZE:
            validate_space(f, args, 2 * sizeof(uint32_t));
            fd = args[1];

            lock_acquire(&fs_lock);
                pcb = thread_current()->pcb;
                if (!valid_fd(pcb, fd)) {
                    f->eax = -1;
                } else {
                    f->eax = file_length(pcb->fdt[fd]);
                }
            lock_release(&fs_lock);
            
            break;
        case SYS_READ:
            validate_space(f, args, (2 * sizeof(uint32_t)) + sizeof(void *) + sizeof(unsigned));
            fd = args[1];
            buff_ptr = (char * ) args[2];
            buff_size = args[3];
            validate_space(f, buff_ptr, buff_size);

            lock_acquire(&fs_lock);
                pcb = thread_current()->pcb;
                if (!valid_fd(pcb, fd) || fd == 1) {
                    f->eax = -1;
                } else if (fd == 0) {
                    /* Read using input_getc from devices/input.c */
                    for (unsigned i = 0; i < buff_size; i++) {
                        buff_ptr[i] = (char) input_getc();
                    }
                    f->eax = buff_size;
                } else {
                    f->eax = file_read(pcb->fdt[fd], buff_ptr, buff_size);
                }
            lock_release(&fs_lock);

            break;
        case SYS_WRITE:
            validate_space(f, args, (2 * sizeof(uint32_t)) + sizeof(void *) + sizeof(unsigned));
            fd = args[1];
            buff_ptr = (char *) args[2];
            buff_size = args[3];
            validate_string(f, buff_ptr);
            
            lock_acquire(&fs_lock);
                pcb = thread_current()->pcb;
                if (!valid_fd(pcb, fd) || fd == 0) {
                    f->eax = -1;
                } else if (fd == 1) {
                    /* Write to console */
                    putbuf(buff_ptr, buff_size);
                } else {
                    f->eax = file_write(pcb->fdt[fd], buff_ptr, buff_size);
                }
            lock_release(&fs_lock);

            break;
        case SYS_SEEK:
            validate_space(f, args, (2 * sizeof(uint32_t)) + sizeof(unsigned));
            fd = args[1];
            unsigned pos = args[2];

            lock_acquire(&fs_lock);
                pcb = thread_current()->pcb;
                if (valid_fd(pcb, fd)) {
                    file_seek(pcb->fdt[fd], pos);
                }
            lock_release(&fs_lock);

            break;
        case SYS_TELL:
            validate_space(f, args, 2 * sizeof(uint32_t));
            fd = args[1];

            lock_acquire(&fs_lock);
                pcb = thread_current()->pcb;
                if (!valid_fd(pcb, fd)) {
                    f->eax = -1;
                } else {
                    f->eax = file_tell(pcb->fdt[fd]);
                }
            lock_release(&fs_lock);

            break;
        case SYS_CLOSE:
            validate_space(f, args, 2 * sizeof(uint32_t));
            fd = args[1];

            lock_acquire(&fs_lock);
                pcb = thread_current()->pcb;
                if (!valid_fd(pcb, fd)) {
                    f->eax = -1;
                } else {
                    file_close(pcb->fdt[fd]);
                    pcb->fdt[fd] = NULL;
                }
            lock_release(&fs_lock);

            break;
        case SYS_COMPUTE_E:
            // int n = args[1];
            // assert(n > 0);
            f->eax = sys_sum_to_e(args[1]);
            break;
        }
}
