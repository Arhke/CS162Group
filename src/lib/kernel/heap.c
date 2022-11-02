#include "heap.h"
#include "../debug.h"


/* Initializes HEAP as empty heap. */
void heap_init(struct heap *heap) {
    *heap = (struct heap) {calloc(1, sizeof(struct heap_elem *)), 0, 1};
}

/* Returns the maximum element in the heap without removing. */
inline struct heap_elem *heap_max(struct heap *heap) {
    if (heap->size == 0) {
        return NULL;
    } else {
        return heap->elems[1];
    }
}

/* Helper functions for heap operations. */
/* Swaps the heap elements at indices i and j. */
void heap_swap(struct heap *heap, int i, int j) {
    struct heap_elem *temp = heap->elems[i];
    heap->elems[i] = heap->elems[j];
    heap->elems[j] = temp;

    heap->elems[i]->heap_index = i;
    heap->elems[j]->heap_index = j;
}

/* Iteratively swaps the element at index with its parent until
    the element is in its correct position. */
void heap_float(struct heap *heap, int index) {
    int parent = index >> 1;
    while (index > 1 && (heap->elems[index]->key > heap->elems[parent]->key)) {
        if (heap->elems[index]->key > heap->elems[parent]->key) {
            heap_swap(heap, index, parent);
            index = parent;
            parent >>= 1;
        } else {
            break;
        }
    }
}

/* Iteratively swaps the element at index with its child until
    the element is in its correct position. */
void heap_sink(struct heap *heap, int index) {
    while (index <= heap->size >> 1) {
        int left_child = index << 1;
        int right_child = (index << 1) + 1;

        int max_child = left_child;
        if (right_child <= heap->size && (heap->elems[right_child]->key > heap->elems[left_child]->key)) {
            max_child = right_child;
        }
        if (heap->elems[index]->key < heap->elems[max_child]->key) {
            heap_swap(heap, index, max_child);
            index = max_child;
        } else {
            break;
        }
    }
}

/* Inserts an element into the heap. */
void heap_insert(struct heap *heap, struct heap_elem *elem) {
    if (heap->size + 1 == heap->capacity) {
        heap->capacity <<= 1;
        heap->elems = realloc(heap->elems, heap->capacity * sizeof(struct heap_elem *));
    }
    heap->size++;
    heap->elems[heap->size] = elem;
    elem->heap_index = heap->size;

    heap_float(heap, heap->size);
}

/* Pops the maximum element from the heap. */
struct heap_elem *heap_pop_max(struct heap *heap) {
    struct heap_elem *result = heap->elems[1];
    heap->elems[1] = heap->elems[heap->size];
    heap->elems[1]->heap_index = 1;
    heap->size--;

    heap_sink(heap, 1);

    if (heap->capacity >= heap->size << 2) {
        heap->capacity >>= 1;
        heap->elems = realloc(heap->elems, heap->capacity * sizeof(struct heap_elem *));
    }
    return result;
}

/* Removes a specific element from the heap. */
void heap_remove(struct heap *heap, struct heap_elem *elem) {
    int index = elem->heap_index;
    heap->elems[index] = heap->elems[heap->size];
    heap->elems[index]->heap_index = index;
    heap->size--;

    heap_sink(heap, index);

    if (heap->capacity >= heap->size << 2) {
        heap->capacity >>= 1;
        heap->elems = realloc(heap->elems, heap->capacity * sizeof(struct heap_elem *));
    };
}

/* Replaces first elem in the heap with second elem. Written as
    a more efficient alternative to heap_pop_max -> heap_insert. */
void heap_replace(struct heap *heap, struct heap_elem *old_elem, struct heap_elem *new_elem) {
    int index = old_elem->heap_index;
    heap->elems[index] = new_elem;
    new_elem->heap_index = index;

    int old_key = old_elem->key, new_key = new_elem->key;
    if (old_key > new_key) {
        heap_sink(heap, index);
    } else if (old_key < new_key) {
        heap_float(heap, index);
    }
}

/* Updates key of element to the given key, either by floating
    or sinking the current element. */
void heap_updateKey(struct heap *heap, struct heap_elem *elem, int key) {
    int old_key = elem->key;
    elem->key = key;

    if (old_key > key) {
        heap_sink(heap, elem->heap_index);
    } else if (old_key < key) {
        heap_float(heap, elem->heap_index);
    }
}

/* Get size of the heap. */
inline size_t heap_size(struct heap *heap) {
    return heap->size;
}

/* Returns if heap is empty or not. */
inline bool heap_empty(struct heap *heap) {
    return heap->size == 0;
}

/* Destroys the heap, freeing allocated space. */
inline void heap_destroy(struct heap *heap) {
    free(heap->elems);
}





