#include "heap.h"
#include "../debug.h"


#define max(a, b) ((a > b) ? a : b)

int highestBit(int n) {
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return (n + 1) >> 1;
}

/* Initializes HEAP as empty heap. */
void heap_init(struct heap *heap) {
    *heap = (struct heap) {NULL, 0, 0};
}

/* Returns the maximum element in the heap without removing. */
inline struct heap_elem *heap_max(struct heap *heap) {
    return heap->root;
}

/* Helper functions for heap operations. */
struct heap_elem *heap_get_index(struct heap *heap, int index) {
    if (index == 0) {
        return NULL;
    } else {
        int next_bit = highestBit(index) >> 1;
        struct heap_elem *cur = heap->root;
        while (next_bit != 0) {
            if ((index & next_bit) == 0) {
                cur = cur->left;
            } else {
                cur = cur->right;
            }
            next_bit >>= 1;
        }
        return cur;
    }
}

void heap_substitute(struct heap *heap, struct heap_elem *old_elem, struct heap_elem *new_elem) {
    int new_key = new_elem->key;
    int new_timestamp = new_elem->time_stamp;

    *new_elem = *old_elem;

    new_elem->key = new_key;
    new_elem->time_stamp = new_timestamp;

    if (old_elem->left != NULL) {
        old_elem->left->parent = new_elem;
    }
    if (old_elem->right != NULL) {
        old_elem->right->parent = new_elem;
    }
    if (old_elem->parent != NULL) {
        if (old_elem == old_elem->parent->left) {
            old_elem->parent->left = new_elem;
        } else {
            old_elem->parent->right = new_elem;
        }
    }
    if (old_elem == heap->root) {
        heap->root = new_elem;
    }
}

/* Swaps elem with its parent. */
void heap_swap_parent(struct heap *heap, struct heap_elem *elem) {
    struct heap_elem *parent = elem->parent;

    struct heap_elem dummy[1];
    heap_substitute(heap, elem, dummy);
    heap_substitute(heap, parent, elem);
    heap_substitute(heap, dummy, parent);
}

/* Iteratively swaps the element at index with its parent until
    the element is in its correct position. */
void heap_float(struct heap *heap, struct heap_elem *elem) {
    while (elem->parent != NULL && (elem->key > elem->parent->key ||
            (elem->key == elem->parent->key && elem->time_stamp < elem->parent->time_stamp))) {
        heap_swap_parent(heap, elem);
    }
}

/* Iteratively swaps the element at index with its child until
    the element is in its correct position. */
void heap_sink(struct heap *heap, struct heap_elem *elem) {
    while (elem->left != NULL || elem->right != NULL) {
        struct heap_elem *max_child = elem->left;
        if (elem->right != NULL && (elem->right->key > elem->left->key ||
                (elem->right->key == elem->left->key && elem->right->time_stamp < elem->left->time_stamp))) {
            max_child = elem->right;
        }
        if (elem->key < max_child->key || (elem->key == max_child->key && elem->time_stamp > max_child->time_stamp)) {
            heap_swap_parent(heap, max_child);
        } else {
            break;
        }
    }
}

/* Inserts an element into the heap. */
void heap_insert(struct heap *heap, struct heap_elem *elem) {
    elem->left = NULL;
    elem->right = NULL;
    elem->time_stamp = heap->clock++;

    if (heap->size == 0) {
        elem->parent = NULL;
        heap->root = elem;
    } else {
        struct heap_elem *parent = heap_get_index(heap, (heap->size + 1) >> 1);
        if (heap->size & 1 == 1) {
            parent->left = elem;
        } else {
            parent->right = elem;
        }
        elem->parent = parent;
        heap_float(heap, elem);
    }
    heap->size++;
}

/* Pops the maximum element from the heap. */
struct heap_elem *heap_pop_max(struct heap *heap) {
    if (heap->size == 0) {
        return NULL;
    } else if (heap->size == 1) {
        struct heap_elem *result = heap->root;
        heap->root = NULL;
        heap->size = 0;
        return result;
    } else {
        struct heap_elem *tail = heap_get_index(heap, heap->size);
        if (heap->size & 1 == 1) {
            tail->parent->right = NULL;
        } else {
            tail->parent->left = NULL;
        }
        struct heap_elem *result = heap->root;
        heap_substitute(heap, result, tail);
        heap_sink(heap, tail);

        heap->size--;
        return result;
    }
}

/* Removes a specific element from the heap. */
void heap_remove(struct heap *heap, struct heap_elem *elem) {
    if (elem == heap->root) {
        heap_pop_max(heap);
    } else {
        struct heap_elem *tail = heap_get_index(heap, heap->size);
        if (tail == tail->parent->left) {
            tail->parent->left = NULL;
        } else {
            tail->parent->right = NULL;
        }
        if (elem != tail) {
            heap_substitute(heap, elem, tail);
            heap_sink(heap, tail);
        }
        heap->size--;
    }
}

/* Updates key of element to the given key, either by floating
    or sinking the current element. */
void heap_updateKey(struct heap *heap, struct heap_elem *elem, int key) {
    elem->key = key;
    heap_sink(heap, elem);
    heap_float(heap, elem);
}

/* Get size of the heap. */
inline size_t heap_size(struct heap *heap) {
    return heap->size;
}

/* Returns if heap is empty or not. */
inline bool heap_empty(struct heap *heap) {
    return heap->size == 0;
}






