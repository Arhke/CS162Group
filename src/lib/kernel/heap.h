#ifndef __LIB_KERNEL_HEAP_H
#define __LIB_KERNEL_HEAP_H


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


/* Heap element. */
struct heap_elem {
    int key;                    /* Key used to compare elem. */
    int time_stamp;             /* Time at which elem is inserted into the heap. */
    struct heap_elem *parent, *left, *right;
};

/* Heap. */
struct heap {
    struct heap_elem *root;     /* Array of elements for array heap implementation */
    int clock;                  /* Clock that marks when elems are inserted into the heap to preserve FIFO order. */
    size_t size;                /* Size of heap */
};

#define heap_entry(HEAP_ELEM, STRUCT, MEMBER) ((STRUCT *) ((uint8_t *) &(HEAP_ELEM)->key - offsetof(STRUCT, MEMBER.key)))

/* Heap initialization. */
void heap_init(struct heap *);

/* Access the heap elements. */
struct heap_elem *heap_get_index(struct heap *, int);
struct heap_elem *heap_max(struct heap *);

/* Heap insertion. */
void heap_insert(struct heap *, struct heap_elem *);

/* Heap removal. */
struct heap_elem *heap_pop_max(struct heap *);
void heap_remove(struct heap *, struct heap_elem *);

/* Heap update. */
void heap_updateKey(struct heap *, struct heap_elem *, int);

/* Heap properties. */
size_t heap_size(struct heap *);
bool heap_empty(struct heap *);


#endif /* lib/kernel/heap.h */
