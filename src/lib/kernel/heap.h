#ifndef __LIB_KERNEL_HEAP_H
#define __LIB_KERNEL_HEAP_H


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


/* Heap element. */
struct heap_elem {
    int key;
    int heap_index;
};

/* Heap. */
struct heap {
    struct heap_elem **elems;   /* Array of elements for array heap implementation */
    size_t size;                /* Size of heap */
    size_t capacity;            /* Capacity of allocated space, used for dynamic reallocation */
};

#define heap_entry(HEAP_ELEM, STRUCT, MEMBER) ((STRUCT *) ((uint8_t *) &(HEAP_ELEM)->key - offsetof(STRUCT, MEMBER.key)))

/* Heap initialization. */
void heap_init(struct heap *);

/* Access the maximum element. */
struct heap_elem *heap_max(struct heap *);

/* Heap insertion. */
void heap_insert(struct heap *, struct heap_elem *);

/* Heap removal. */
struct heap_elem *heap_pop_max(struct heap *);
void heap_remove(struct heap *, struct heap_elem *);
void heap_replace(struct heap *, struct heap_elem *, struct heap_elem *);

/* Heap update. */
void heap_updateKey(struct heap *, struct heap_elem *, int);

/* Heap properties. */
size_t heap_size(struct heap *);
bool heap_empty(struct heap *);

/* Destroy heap. */
void heap_destroy(struct heap *);

#endif /* lib/kernel/heap.h */
