
#ifndef FILESYS_BUFFER_H
#define FILESYS_BUFFER_H

#include <stdbool.h>
#include <limits.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"

#define NUM_CACHE_BLOCKS 64
#define bitnum(n) (63 - __builtin_clzll(n))


void buffer_cache_init(void);

void buffer_cache_read(block_sector_t, void *);
void buffer_cache_read_chunk(block_sector_t, int, int, void *);
void buffer_cache_write(block_sector_t, void *);
void buffer_cache_write_chunk(block_sector_t, int, int, void *);
void buffer_cache_zero(block_sector_t);
void buffer_cache_invalidate(block_sector_t);
void buffer_cache_flush(void);


#endif /* filesys/buffer.h */