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


/* Argument validation macros: In order for a pointer to be valid, must be below PHYS_BASE
    and have a mapping in the page directory */

/* Validates n bytes of space starting at ptr by validating the start and end addresses */
#define validate_space(if_, ptr, n) ({                                                                          \
    if ((void *) ((char *) ptr + n) > PHYS_BASE ||                                                              \
            !(pagedir_get_page(active_pd(), ptr) && pagedir_get_page(active_pd(), (char *) ptr + n - 1))) {     \
        process_exit(-1);                                                                                       \
        return;                                                                                                 \
    }                                                                                                           \
})

/* Validates a string starting at str by iterating one byte at a time and looking for the null terminator */
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



static void syscall_handler(struct intr_frame *);

void syscall_init(void) {lock_init(&fs_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f) {
    uint32_t* args = ((uint32_t*)f->esp);
    /* Checks that the syscall number lies within bounds of the address space */
    validate_space(f, args, sizeof(uint32_t));

    /*
    * The following print statement, if uncommented, will print out the syscall
    * number whenever a process enters a system call. You might find it useful
    * when debugging. It will cause tests to fail, however, so you should not
    * include it in your final submission.
    */
    // printf("Process %s executing system call number: %d\n", thread_current()->pcb->process_name, args[0]);

    /* Get the current thread's pcb */
    struct process* pcb = thread_current()->pcb;

    /* Setup common variable names for file syscalls */
    char* file_name;
    struct file* desc;
    int fd;
    unsigned buff_size;
    char* buff_ptr;

    switch (args[0]) {
        case SYS_PRACTICE:
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* Add one to argument, return to eax */
            f->eax = args[1] + 1;

            break;
        case SYS_HALT:
            /* Call shutdown power off, nothing else to be done */
            shutdown_power_off();

            break;
        case SYS_EXIT:
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* Loads argument first then calls process_exit */
            f->eax = args[1];
            process_exit(args[1]);

            break;
        case SYS_EXEC:
            validate_space(f, args, 2 * sizeof(uint32_t));
            file_name = (char *) args[1];
            validate_string(f, file_name);

            /* Put return value PID of execute into eax */
            f->eax = process_execute((char *) args[1]);

            break;
        case SYS_WAIT:
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* Call wait on the child PID */
            f->eax = process_wait(args[1]);

            break;
        case SYS_CREATE:
            /* Validate and copy arguments */
            validate_space(f, args, sizeof(uint32_t) + sizeof(char *) + sizeof(unsigned));
            file_name = (char *) args[1];
            validate_string(f, file_name);
            int32_t initial_size = args[2];

            /* Call filesys_create helper function and store return value in eax */
            f->eax = filesys_create(file_name, initial_size);

            break;
        case SYS_REMOVE:
            /* Validate and copy arguments */
            validate_space(f, args, sizeof(uint32_t) + sizeof(char *));
            file_name = (char *) args[1];
            validate_string(f, file_name);

            /* Call filesys_remove helper function and store return value in eax */
            f->eax = filesys_remove(file_name);

            break;
        case SYS_OPEN:
            /* Validate and copy arguments */
            validate_space(f, args, sizeof(uint32_t) + sizeof(char *));
            file_name = (char *) args[1];
            validate_string(f, file_name);

            /* Find the next open file descriptor in file descriptor table */
            fd = open_fd(pcb);
            /* If no file descriptor is available, return -1 */
            if (fd == -1) {
                f->eax = -1;
            } else {
                /* Open the file and add the description to the file descriptor 
                    * table at index fd, or return -1 if the file could not be opened 
                    */
                desc = filesys_open(file_name);
                if (desc == NULL) {
                    f->eax = -1;
                } else {
                    pcb->fdt[fd] = desc;
                    f->eax = fd;
                }
            }
                
            break;
        case SYS_FILESIZE:
            /* Validate and copy arguments */
            validate_space(f, args, 2 * sizeof(uint32_t));
            fd = args[1];

            /* Call the file_length helper function, or return -1 if the file descriptor is invalid in this process */
            if (!valid_fd(pcb, fd)) {
                f->eax = -1;
            } else {
                f->eax = file_length(pcb->fdt[fd]);
            }
            
            break;
        case SYS_READ:
            /* Validate and copy arguments */
            validate_space(f, args, (2 * sizeof(uint32_t)) + sizeof(void *) + sizeof(unsigned));
            fd = args[1];
            buff_ptr = (char * ) args[2];
            buff_size = args[3];
            validate_space(f, buff_ptr, buff_size);

            /* If the file descriptor is invalid, return -1 */
            if (!valid_fd(pcb, fd) || fd == 1) {
                f->eax = -1;
            } else if (fd == 0) {
                /* Reading from stdin */
                lock_acquire(&input_lock);
                    /* Read using input_getc from devices/input.c */
                    for (unsigned i = 0; i < buff_size; i++) {
                        buff_ptr[i] = (char) input_getc();
                    }
                lock_release(&input_lock);
                /* Return number of bytes read */
                f->eax = buff_size;
            } else {
                /* Reading from a file using file_read helper and storing number of bytes read in eax */
                f->eax = file_read(pcb->fdt[fd], buff_ptr, buff_size);
            }

            break;
        case SYS_WRITE:
            /* Validate and copy arguments */
            validate_space(f, args, (2 * sizeof(uint32_t)) + sizeof(void *) + sizeof(unsigned));
            fd = args[1];
            buff_ptr = (char *) args[2];
            buff_size = args[3];
            validate_string(f, buff_ptr);
            
            /* If the file descriptor is invalid, return -1 */
            if (!valid_fd(pcb, fd) || fd == 0) {
                f->eax = -1;
            } else if (fd == 1) {
                /* Write to console if the file descriptor is 1 for stdout */
                putbuf(buff_ptr, buff_size);
            } else {
                /* Write to a file using file_write helper function and store number of bytes read in eax */
                f->eax = file_write(pcb->fdt[fd], buff_ptr, buff_size);
            }

            break;
        case SYS_SEEK:
            /* Validate and copy arguments */
            validate_space(f, args, (2 * sizeof(uint32_t)) + sizeof(unsigned));
            fd = args[1];
            unsigned pos = args[2];

            /* Call file_seek on the file pointed to by the given file descriptor if it is valid. Otherwise, do nothing. */
            if (valid_fd(pcb, fd)) {
                file_seek(pcb->fdt[fd], pos);
            }

            break;
        case SYS_TELL:
            /* Validate and copy arguments */
            validate_space(f, args, 2 * sizeof(uint32_t));
            fd = args[1];

            /* If the file descriptor is invalid, return -1. Otherwise, call the file_tell helper function and put the result in eax. */
            if (!valid_fd(pcb, fd)) {
                f->eax = -1;
            } else {
                f->eax = file_tell(pcb->fdt[fd]);
            }

            break;
        case SYS_CLOSE:
            /* Validate and copy arguments */
            validate_space(f, args, 2 * sizeof(uint32_t));
            fd = args[1];

            /* Call file close on the given fd and update the file descriptor table, or return -1 if the file descriptor is invalid. */
            if (!valid_fd(pcb, fd)) {
                f->eax = -1;
            } else {
                file_close(pcb->fdt[fd]);
                pcb->fdt[fd] = NULL;
            }

            break;
        case SYS_COMPUTE_E:
            /* Validate arguments */
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* Call the sys_sum_to_e helper function and put the return value in eax. */
            f->eax = sys_sum_to_e(args[1]);

            break;
        }
}
