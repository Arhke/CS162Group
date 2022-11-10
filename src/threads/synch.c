/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.
   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.
   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:
   - down or "P": wait for the value to become positive, then
     decrement it.
   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void sema_init(struct semaphore* sema, unsigned value) {
    ASSERT(sema != NULL);

    sema->value = value;
    heap_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.
   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void sema_down(struct semaphore* sema) {
    enum intr_level old_level;

    ASSERT(sema != NULL);
    ASSERT(!intr_context());

    old_level = intr_disable();
    while (sema->value == 0) {
        /* Add this thread to the heap of semaphore waiters. */
        heap_insert(&sema->waiters, &thread_current()->heap_elem);

        /* Set the current heap that this thread resides on to the waiters heap. */
        thread_current()->current_heap = &sema->waiters;

        thread_block();
    }
    sema->value--;
    thread_current()->current_heap = NULL;

    intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.
   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore* sema) {
    enum intr_level old_level;
    bool success;

    ASSERT(sema != NULL);

    old_level = intr_disable();
    if (sema->value > 0) {
        sema->value--;
        success = true;
    } else
        success = false;
    intr_set_level(old_level);

    return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.
   This function may be called from an interrupt handler. */
void sema_up(struct semaphore* sema) {
    enum intr_level old_level;

    ASSERT(sema != NULL);

    old_level = intr_disable();
    if (!heap_empty(&sema->waiters))
        thread_unblock(heap_entry(heap_pop_max(&sema->waiters), struct thread, heap_elem));
    sema->value++;
    
    /* If the highest ready thread is of higher priority, then yield. */
    if (!intr_context() && !heap_empty(&prio_ready_heap) && thread_current()->effective_priority < heap_max(&prio_ready_heap)->key) {
        intr_set_level(old_level);
        thread_yield();
    } else {
        intr_set_level(old_level);
    }
}

static void sema_test_helper(void* sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
    struct semaphore sema[2];
    int i;

    printf("Testing semaphores...");
    sema_init(&sema[0], 0);
    sema_init(&sema[1], 0);
    thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
    for (i = 0; i < 10; i++) {
        sema_up(&sema[0]);
        sema_down(&sema[1]);
    }
    printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void* sema_) {
    struct semaphore* sema = sema_;
    int i;

    for (i = 0; i < 10; i++) {
        sema_down(&sema[0]);
        sema_up(&sema[1]);
    }
}

void lock_refresh_donors(struct lock *lock) {
    ASSERT(lock != NULL);

    int old_max_donor = lock->elem.key, new_max_donor;
    if (heap_empty(&lock->waiters)) {
        new_max_donor = 0;
    } else {
        new_max_donor = heap_max(&lock->waiters)->key;
    }

    if (lock->holder == NULL || new_max_donor == old_max_donor) {
        lock->elem.key = new_max_donor;
        return;
    } else {
        heap_updateKey(&lock->holder->held_locks, &lock->elem, new_max_donor);
        thread_refresh_priority(lock->holder);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.
   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock* lock) {
    ASSERT(lock != NULL);
    lock->holder = NULL;
    lock->elem.key = 0;
    heap_init(&lock->waiters);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.
   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire(struct lock* lock) {
    enum intr_level old_level;

    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(!lock_held_by_current_thread(lock));

    old_level = intr_disable();
    while (lock->holder != NULL) {
        /* Add current threaad to list of waiters, set the current heap to the waiters heap, and mark the waiting lock. */
        heap_insert(&lock->waiters, &thread_current()->heap_elem);
        thread_current()->current_heap = &lock->waiters;
        thread_current()->waiting_lock = lock;

        /* Refresh the lock's maximum donated priority, and any changes in effective priority higher up. */
        lock_refresh_donors(lock);
        thread_block();
    }
    
    /* Now that the lock has been acquired, set holder to current, and mark current heap and waiting lock to NULL. */
    lock->holder = thread_current();
    thread_current()->current_heap = NULL;
    thread_current()->waiting_lock = NULL;

    /* Add lock to list of held locks, and refresh effective priority as a result of acquiring the lock. */
    heap_insert(&thread_current()->held_locks, &lock->elem);
    thread_refresh_priority(thread_current());

    intr_set_level(old_level);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.
   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock* lock) {
    bool success;
    enum intr_level old_level;

    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(!lock_held_by_current_thread(lock));

    old_level = intr_disable();
    if (lock->holder != NULL) {
        success = false;
    } else {
        /* If the lock is not currently held, set the new holder, and add the lock to list of held locks. */
        lock->holder = thread_current();
        heap_insert(&thread_current()->held_locks, &lock->elem);

        /* Update the effective priority of threads and threads higher up to reflect new effective priority. */
        thread_refresh_priority(thread_current());
        success = true;
    }

    intr_set_level(old_level);
    return success;
}

/* Releases LOCK, which must be owned by the current thread.
   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock* lock) {
    enum intr_level old_level;

    ASSERT(lock != NULL);
    ASSERT(lock_held_by_current_thread(lock));

    old_level = intr_disable();

    /* Once the lock is released, the lock is no longer on the heap of held locks. */
    lock->holder = NULL;
    heap_remove(&thread_current()->held_locks, &lock->elem);

    if (!heap_empty(&lock->waiters)) {
        /* Unblock the next thread to be run. */
        thread_unblock(heap_entry(heap_pop_max(&lock->waiters), struct thread, heap_elem));
    }

    /* Update the lock's key to match the maximum donated priority. */
    if (heap_empty(&lock->waiters)) {
        lock->elem.key = 0;
    } else {
        lock->elem.key = heap_max(&lock->waiters)->key;
    }

    /* Update the effective priority of threads and threads higher up to reflect new effective priority. */
    thread_refresh_priority(thread_current());

    /* If the highest ready thread is of higher priority, then yield. */
    if (!heap_empty(&prio_ready_heap) && thread_current()->effective_priority < heap_max(&prio_ready_heap)->key) {
        intr_set_level(old_level);
        thread_yield();
    } else {
        intr_set_level(old_level);
    }
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock* lock) {
    ASSERT(lock != NULL);

    return lock->holder == thread_current();
}

/* Initializes a readers-writers lock */
void rw_lock_init(struct rw_lock* rw_lock) {
    lock_init(&rw_lock->lock);
    cond_init(&rw_lock->read);
    cond_init(&rw_lock->write);
    rw_lock->AR = rw_lock->WR = rw_lock->AW = rw_lock->WW = 0;
}

/* Acquire a writer-centric readers-writers lock */
void rw_lock_acquire(struct rw_lock* rw_lock, bool reader) {
    // Must hold the guard lock the entire time
    lock_acquire(&rw_lock->lock);

    if (reader) {
        // Reader code: Block while there are waiting or active writers
        while ((rw_lock->AW + rw_lock->WW) > 0) {
            rw_lock->WR++;
            cond_wait(&rw_lock->read, &rw_lock->lock);
            rw_lock->WR--;
        }
        rw_lock->AR++;
  } else {
    // Writer code: Block while there are any active readers/writers in the system
        while ((rw_lock->AR + rw_lock->AW) > 0) {
            rw_lock->WW++;
            cond_wait(&rw_lock->write, &rw_lock->lock);
            rw_lock->WW--;
        }
        rw_lock->AW++;
  }

    // Release guard lock
    lock_release(&rw_lock->lock);
}

/* Release a writer-centric readers-writers lock */
void rw_lock_release(struct rw_lock* rw_lock, bool reader) {
  // Must hold the guard lock the entire time
    lock_acquire(&rw_lock->lock);

    if (reader) {
        // Reader code: Wake any waiting writers if we are the last reader
        rw_lock->AR--;
        if (rw_lock->AR == 0 && rw_lock->WW > 0)
            cond_signal(&rw_lock->write, &rw_lock->lock);
    } else {
        // Writer code: First try to wake a waiting writer, otherwise all waiting readers
        rw_lock->AW--;
        if (rw_lock->WW > 0)
            cond_signal(&rw_lock->write, &rw_lock->lock);
        else if (rw_lock->WR > 0)
            cond_broadcast(&rw_lock->read, &rw_lock->lock);
    }

    // Release guard lock
    lock_release(&rw_lock->lock);
}


/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition* cond) {
    ASSERT(cond != NULL);

    heap_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.
   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.
   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.
   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition* cond, struct lock* lock) {
    enum intr_level old_level;

    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    old_level = intr_disable();

    /* Add the current thread to the list of waiters and set the current heap variable. */
    heap_insert(&cond->waiters, &thread_current()->heap_elem);
    thread_current()->current_heap = &cond->waiters;

    lock_release(lock);
    thread_block();
    lock_acquire(lock);

    /* Since the current thread is now running again, set the current heap to NULL. */
    thread_current()->current_heap = NULL;

    intr_set_level(old_level);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.
   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition* cond, struct lock* lock UNUSED) {
    enum intr_level old_level;

    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    old_level = intr_disable();
    if (!heap_empty(&cond->waiters))
        /* Unblock the next thread to be run. */
        thread_unblock(heap_entry(heap_pop_max(&cond->waiters), struct thread, heap_elem));

    /* If the highest ready thread is of higher priority, then yield. */
    if (!heap_empty(&prio_ready_heap) && thread_current()->effective_priority < heap_max(&prio_ready_heap)->key) {
        thread_yield();
        intr_set_level(old_level);
    } else {
        intr_set_level(old_level);
    }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.
   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition* cond, struct lock* lock) {
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);

    while (!heap_empty(&cond->waiters))
        cond_signal(cond, lock);
}
