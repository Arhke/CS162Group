#include "filesys/buffer.h"
#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "threads/synch.h"
#include <stdlib.h>


static struct lock buffer_cache_lock;

static char buffer_cache_space[NUM_CACHE_BLOCKS << BLOCK_SECTOR_BITS];
static void *buffer_cache_blocks[NUM_CACHE_BLOCKS];
static block_sector_t sector_indices[NUM_CACHE_BLOCKS];
static int64_t dirty_bits;
static int64_t valid_bits;
static int64_t access_bits;
static int64_t clock_hand;


void buffer_cache_init(void) {
    lock_init(&buffer_cache_lock);
    for (int i = 0; i < NUM_CACHE_BLOCKS; i++) {
        buffer_cache_blocks[i] = (void *) (buffer_cache_space + (i << BLOCK_SECTOR_BITS));
    }
    valid_bits = 0;
    clock_hand = 0;
}


int buffer_cache_find_sector(block_sector_t sector_idx) {
    int64_t mask = 1ULL;
    for (int i = 0; i < NUM_CACHE_BLOCKS; i++) {
        if ((valid_bits & mask) != 0 && sector_indices[i] == sector_idx) {
            access_bits |= mask;
            return i;
        }
        mask <<= 1;
    }
    return -1;
}


int buffer_cache_allocate_sector(block_sector_t sector_idx) {
    access_bits &= valid_bits;
    int64_t mask = 1ULL << clock_hand;

    int64_t old_access_bits = access_bits;
    access_bits += mask;
    mask = access_bits & ~old_access_bits;
    if (mask == 0) {
        old_access_bits = access_bits;
        access_bits++;
        mask = access_bits & ~old_access_bits;
    }
    clock_hand = bitnum(mask);
    int64_t cache_block_num = clock_hand;

    if ((valid_bits & dirty_bits & mask) != 0) {
        block_write(fs_device, sector_indices[cache_block_num], buffer_cache_blocks[cache_block_num]);
    }
    sector_indices[cache_block_num] = sector_idx;
    valid_bits |= mask;
    dirty_bits &= ~mask;
    access_bits |= mask;
    return cache_block_num;
}


int buffer_cache_find_or_allocate_sector(block_sector_t sector_idx) {
    int result = buffer_cache_find_sector(sector_idx);
    if (result != -1) {
        return result;
    } else {
        return buffer_cache_allocate_sector(sector_idx);
    }
}


int buffer_cache_get_sector(block_sector_t sector_idx) {
    int result = buffer_cache_find_sector(sector_idx);
    if (result != -1) {
        return result;
    } else {
        result = buffer_cache_allocate_sector(sector_idx);
        block_read(fs_device, sector_idx, buffer_cache_blocks[result]);
        return result;
    }
}


void buffer_cache_read(block_sector_t sector_idx, void *buf) {
    lock_acquire(&buffer_cache_lock);
        int64_t cache_block_index = buffer_cache_get_sector(sector_idx);
        memcpy(buf, buffer_cache_blocks[cache_block_index], BLOCK_SECTOR_SIZE);
    lock_release(&buffer_cache_lock);
}


void buffer_cache_read_chunk(block_sector_t sector_idx, int sector_ofs, int chunk_size, void *buf) {
    ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
    lock_acquire(&buffer_cache_lock);
        int64_t cache_block_index = buffer_cache_get_sector(sector_idx);
        memcpy(buf, buffer_cache_blocks[cache_block_index] + sector_ofs, chunk_size);
    lock_release(&buffer_cache_lock);
}


void buffer_cache_write(block_sector_t sector_idx, void *buf) {
    lock_acquire(&buffer_cache_lock);
        int64_t cache_block_index = buffer_cache_find_or_allocate_sector(sector_idx);
        memcpy(buffer_cache_blocks[cache_block_index], buf, BLOCK_SECTOR_SIZE);
        dirty_bits |= (1ULL << cache_block_index);
    lock_release(&buffer_cache_lock);
}


void buffer_cache_write_chunk(block_sector_t sector_idx, int sector_ofs, int chunk_size, void *buf) {
    ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
    lock_acquire(&buffer_cache_lock);
        int64_t cache_block_index = buffer_cache_find_or_allocate_sector(sector_idx);
        memcpy(buffer_cache_blocks[cache_block_index] + sector_ofs, buf, chunk_size);
        dirty_bits |= (1ULL << cache_block_index);
    lock_release(&buffer_cache_lock);
}


void buffer_cache_zero(block_sector_t sector_idx) {
    lock_acquire(&buffer_cache_lock);
        int64_t cache_block_index = buffer_cache_find_or_allocate_sector(sector_idx);
        memset(buffer_cache_blocks[cache_block_index], 0, BLOCK_SECTOR_SIZE);
        dirty_bits |= (1ULL << cache_block_index);
    lock_release(&buffer_cache_lock);
}


void buffer_cache_invalidate(block_sector_t sector_idx) {
    lock_acquire(&buffer_cache_lock);
        int64_t cache_block_index = buffer_cache_find_sector(sector_idx);
        if (cache_block_index != -1) {
            valid_bits &= ~(1ULL << cache_block_index);
        }
    lock_release(&buffer_cache_lock);
}


void buffer_cache_flush(void) {
    int64_t mask = 1ULL;
    dirty_bits &= valid_bits;
    for (int i = 0; i < NUM_CACHE_BLOCKS; i++) {
        if ((dirty_bits & mask) != 0) {
            block_write(fs_device, sector_indices[i], buffer_cache_blocks[i]);
        }
        mask <<= 1;
    }
    dirty_bits = 0;
}




