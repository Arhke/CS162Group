#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */

typedef struct child_data;

struct process {
    /* Owned by process.c. */
    uint32_t* pagedir;                  /* Page directory. */
    char process_name[16];              /* Name of the main thread */
    struct thread* main_thread;         /* Pointer to main thread */


    struct process *parent_process;     /* Pointer to parent process */
    struct list child_processes;        /* List of struct child_data representing child processes */

    struct semaphore pcb_init_sema;     /* Semaphore that ensures child PCB is initialized before parent finishes exec */
    struct semaphore wait_sema;         /* Semaphore that ensures child finishes executing before parent finishes wait */

    struct rw_lock list_iteration_lock; /* Synchronization of child/parent list iteration and list element insertion/
                                            deletion. To iterate, use reader, to add element, use writer. */
};

struct child_data {
    struct process *child_process;      /* Pointer to the child process */
    pid_t pid;                          /* PID of child process */
    struct lock elem_modification_lock; /* Synchronization of concurrent read/writes to child_data */
    bool is_waiting;                    /* Whether parent is waiting on this child */
    bool has_exited;                    /* Whether this child process has exited or not */
    uint32_t exit_code;                 /* Exit code of child process */
    struct list_elem elem;
};


bool setup_pcb(void);
void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(int);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
