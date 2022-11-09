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
    and have a mapping in the page directory. */

/* Validates n bytes of space starting at ptr by validating the start and end addresses. */


bool is_valid_user_vaddr(void *ptr) {
    return pagedir_get_page(active_pd(), ptr) != NULL;
}


#define validate_space(if_, ptr, n) ({                                                                          \
    if ((void *) ptr + n > PHYS_BASE ||                                                                         \
            !(is_valid_user_vaddr(ptr) && is_valid_user_vaddr((void *) ptr + n - 1))) {                         \
        process_exit(-1);                                                                                       \
        return;                                                                                                 \
    }                                                                                                           \
})

/* Validates a string starting at str by iterating one byte at a time and looking for the null terminator */
#define validate_string(if_, str) ({                                                                            \
    if ((void *) str >= PHYS_BASE || !is_valid_user_vaddr(str)) {                                               \
        process_exit(-1);                                                                                       \
        return;                                                                                                 \
    }                                                                                                           \
    char *cptr = (char *) str;                                                                                  \
    while ((void *) cptr < PHYS_BASE && is_valid_user_vaddr(cptr) && *(cptr++));                                                                                                                                       \
    if (!is_valid_user_vaddr(cptr)) {                                                                           \
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

    /* Setup common variable names for syscalls */
    char* file_name;
    struct file* desc;
    int fd;
    unsigned buff_size;
    char* buff_ptr;

    struct list_elem *e;
    struct userspace_lock_container *ulc;
    struct userspace_sema_container *usc;

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

            /* Acquire the global filesystem lock to prevent modification of the executable before running */
            lock_acquire(&fs_lock);
                /* Put return value PID of execute into eax */
                f->eax = process_execute((char *) args[1]);
            lock_release(&fs_lock);

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
            lock_acquire(&fs_lock);
                f->eax = filesys_create(file_name, initial_size);
            lock_release(&fs_lock);

            break;
        case SYS_REMOVE:
            /* Validate and copy arguments */
            validate_space(f, args, sizeof(uint32_t) + sizeof(char *));
            file_name = (char *) args[1];
            validate_string(f, file_name);

            /* Call filesys_remove helper function and store return value in eax */
            lock_acquire(&fs_lock);
                f->eax = filesys_remove(file_name);
            lock_release(&fs_lock);

            break;
        case SYS_OPEN:
            /* Validate and copy arguments */
            validate_space(f, args, sizeof(uint32_t) + sizeof(char *));
            file_name = (char *) args[1];
            validate_string(f, file_name);

            /* Find the next open file descriptor in file descriptor table */
            lock_acquire(&fs_lock);
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
            lock_release(&fs_lock);
                
            break;
        case SYS_FILESIZE:
            /* Validate and copy arguments */
            validate_space(f, args, 2 * sizeof(uint32_t));
            fd = args[1];

            /* Call the file_length helper function, or return -1 if the file descriptor is invalid in this process */
            if (!valid_fd(pcb, fd)) {
                f->eax = -1;
            } else {
                lock_acquire(&fs_lock);
                    f->eax = file_length(pcb->fdt[fd]);
                lock_release(&fs_lock);
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
                lock_acquire(&fs_lock);
                    /* Read using input_getc from devices/input.c */
                    for (unsigned i = 0; i < buff_size; i++) {
                        buff_ptr[i] = (char) input_getc();
                    }
                lock_release(&fs_lock);
                /* Return number of bytes read */
                f->eax = buff_size;
            } else {
                /* Reading from a file using file_read helper and storing number of bytes read in eax */
                lock_acquire(&fs_lock);
                    f->eax = file_read(pcb->fdt[fd], buff_ptr, buff_size);
                lock_release(&fs_lock);
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
                lock_acquire(&fs_lock);
                    putbuf(buff_ptr, buff_size);
                lock_release(&fs_lock);
            } else {
                /* Write to a file using file_write helper function and store number of bytes read in eax */
                lock_acquire(&fs_lock);
                    f->eax = file_write(pcb->fdt[fd], buff_ptr, buff_size);
                lock_release(&fs_lock);
            }

            break;
        case SYS_SEEK:
            /* Validate and copy arguments */
            validate_space(f, args, (2 * sizeof(uint32_t)) + sizeof(unsigned));
            fd = args[1];
            unsigned pos = args[2];

            /* Call file_seek on the file pointed to by the given file descriptor if it is valid. Otherwise, do nothing. */
            if (valid_fd(pcb, fd)) {
                lock_acquire(&fs_lock);
                    file_seek(pcb->fdt[fd], pos);
                lock_release(&fs_lock);
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
                lock_acquire(&fs_lock);
                    f->eax = file_tell(pcb->fdt[fd]);
                lock_release(&fs_lock);
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
                lock_acquire(&fs_lock);
                    file_close(pcb->fdt[fd]);
                lock_release(&fs_lock);
                pcb->fdt[fd] = NULL;
            }

            break;
        case SYS_COMPUTE_E:
            /* Validate arguments */
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* Call the sys_sum_to_e helper function and put the return value in eax. */
            f->eax = sys_sum_to_e(args[1]);

            break;
        case SYS_PT_CREATE:
            /* Validate arguments */
            validate_space(f, args, 4 * sizeof(uint32_t));

            /* Call pthread_execute helper function to create thread. */
            f->eax = pthread_execute((stub_fun) args[1], (pthread_fun) args[2], (void *) args[3]);

            break;
        case SYS_PT_EXIT:
            /* Call pthread_exit or pthread_exit_main depending on thread. */
            if (thread_current() ==  pcb->main_thread) {
                pthread_exit_main();
            } else {
                pthread_exit();
            }

            break;
        case SYS_PT_JOIN:
            /* Validate arguments */
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* Call pthread_join on the input TID. */
            f->eax = pthread_join((tid_t) args[1]);

            break;
        case SYS_LOCK_INIT:
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* The provided address must point to valid userspace or else the syscall fails. */
            if (!is_valid_user_vaddr(args[1])) {
                f->eax = false;
            } else {
                /* Allocate space for a new kernel lock to userspace lock mapping. */
                ulc = malloc(sizeof(struct userspace_lock_container));
                if (ulc == NULL) {
                    f->eax = false;
                } else {
                    /* Initialize the kernel lock and map it to the userspace address. */
                    lock_init(&ulc->lock);
                    ulc->userspace_addr = (void *) args[1];

                    /* Add the new mapping to the list of process locks. */
                    lock_acquire(&pcb->process_locks_lock);
                        list_push_back(&pcb->process_locks, &ulc->elem);
                    lock_release(&pcb->process_locks_lock);
                    f->eax = true;
                }
            }

            break;
        case SYS_LOCK_ACQUIRE:
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* The provided address must point to valid userspace or else the syscall fails. */
            if (!is_valid_user_vaddr(args[1])) {
                f->eax = false;
            } else {
                e = list_begin(&pcb->process_locks);

                lock_acquire(&pcb->process_locks_lock);
                    /* Iterate through the list of process locks while searching for a matching userspace address. */
                    while (e != list_end(&pcb->process_locks)) {
                        ulc = list_entry(e, struct userspace_lock_container, elem);
                        if (ulc->userspace_addr == (void *) args[1]) {
                            break;
                        }
                        e = list_next(e);
                    }
                lock_release(&pcb->process_locks_lock);
                
                /* Once a matching kernel lock is found, check the cases. If no match exists or lock is already held,
                    then fails, else succeeds. */
                if (e == list_end(&pcb->process_locks) || ulc->lock.holder == thread_current()) {
                    f->eax = false;
                } else {
                    lock_acquire(&ulc->lock);
                    f->eax = true;
                }
            }

            break;
        case SYS_LOCK_RELEASE:
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* The provided address must point to valid userspace or else the syscall fails. */
            if (!is_valid_user_vaddr(args[1])) {
                f->eax = false;
            } else {
                e = list_begin(&pcb->process_locks);

                lock_acquire(&pcb->process_locks_lock);
                    /* Iterate through the list of process locks while searching for a matching userspace address. */
                    while (e != list_end(&pcb->process_locks)) {
                        ulc = list_entry(e, struct userspace_lock_container, elem);
                        if (ulc->userspace_addr == (void *) args[1]) {
                            break;
                        }
                        e = list_next(e);
                    }
                lock_release(&pcb->process_locks_lock);
                
                /* Once a matching kernel lock is found, check the cases. If no match exists or lock not already held,
                    then fails, else succeeds. */
                if (e == list_end(&pcb->process_locks) || ulc->lock.holder != thread_current()) {
                    f->eax = false;
                } else {
                    lock_release(&ulc->lock);
                    f->eax = true;
                }
            }

            break;
        case SYS_SEMA_INIT:
            validate_space(f, args, 3 * sizeof(uint32_t));

            /* The provided address must point to valid userspace or else the syscall fails. */
            if (!is_valid_user_vaddr(args[1]) || (int) args[2] < 0) {
                f->eax = false;
            } else {
                /* Allocate space for a new kernel semaphore to userspace semaphore mapping. */
                usc = malloc(sizeof(struct userspace_sema_container));
                if (usc == NULL) {
                    f->eax = false;
                } else {
                    /* Initialize the kernel semaphore and map it to the userspace address. */
                    sema_init(&usc->sema, args[2]);
                    usc->userspace_addr = (void *) args[1];

                    /* Add the new mapping to the list of process semaphores. */
                    lock_acquire(&pcb->process_semas_lock);
                        list_push_back(&pcb->process_semas, &usc->elem);
                    lock_release(&pcb->process_semas_lock);
                    f->eax = true;
                }
            }

            break;
        case SYS_SEMA_DOWN:
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* The provided address must point to valid userspace or else the syscall fails. */
            if (!is_valid_user_vaddr(args[1])) {
                f->eax = false;
            } else {
                e = list_begin(&pcb->process_semas);

                lock_acquire(&pcb->process_semas_lock);
                    /* Iterate through the list of process semaphores while searching for a matching userspace address. */
                    while (e != list_end(&pcb->process_semas)) {
                        usc = list_entry(e, struct userspace_sema_container, elem);
                        if (usc->userspace_addr == (void *) args[1]) {
                            break;
                        }
                        e = list_next(e);
                    }
                lock_release(&pcb->process_semas_lock);
                
                /* Once a matching kernel lock is found, check the cases. If no match exists,
                    then fails, else succeeds. */
                if (e == list_end(&pcb->process_semas)) {
                    f->eax = false;
                } else {
                    sema_down(&usc->sema);
                    f->eax = true;
                }
            }

            break;
        case SYS_SEMA_UP:
            validate_space(f, args, 2 * sizeof(uint32_t));

            /* The provided address must point to valid userspace or else the syscall fails. */
            if (!is_valid_user_vaddr(args[1])) {
                f->eax = false;
            } else {
                e = list_begin(&pcb->process_semas);

                lock_acquire(&pcb->process_semas_lock);
                    /* Iterate through the list of process semaphores while searching for a matching userspace address. */
                    while (e != list_end(&pcb->process_semas)) {
                        usc = list_entry(e, struct userspace_sema_container, elem);
                        if (usc->userspace_addr == (void *) args[1]) {
                            break;
                        }
                        e = list_next(e);
                    }
                lock_release(&pcb->process_semas_lock);
                
                /* Once a matching kernel lock is found, check the cases. If no match exists,
                    then fails, else succeeds. */
                if (e == list_end(&pcb->process_semas)) {
                    f->eax = false;
                } else {
                    sema_up(&usc->sema);
                    f->eax = true;
                }
            }

            break;
        case SYS_GET_TID:
            /* Nothing fancy, literally just return the TID. */
            f->eax = thread_current()->tid;

            break;
    }
    /* If this is marked true, then some thread has made the exit syscall and declared that the the process should
        terminate. All threads should be terminated if they try to go back to user mode. */
    if (pcb->forced_exit) {
        thread_exit();
    }
}
