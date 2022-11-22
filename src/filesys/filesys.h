#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include <limits.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */

#define NUM_CACHE_BLOCKS 64
#define bitnum(n) (31 - __builtin_clz(n))

/* Block device that contains the file system. */
extern struct block* fs_device;
extern void *buffer_cache_blocks[NUM_CACHE_BLOCKS];
extern int64_t dirty_bits;

/* Global filesystem lock. */
extern struct lock fs_lock;
extern struct lock buffer_cache_lock;

void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(const char* name, off_t initial_size);
struct file* filesys_open(const char* name);
bool filesys_remove(const char* name);

int buffer_cache_find_sector(block_sector_t);
int buffer_cache_allocate_sector(block_sector_t);
int buffer_cache_find_or_allocate_sector(block_sector_t);
int buffer_cache_get_sector(block_sector_t);

#endif /* filesys/filesys.h */
