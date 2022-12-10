#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include <limits.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "filesys/directory.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */


struct fdt_entry {
    struct dir* dir;
    struct file* file;
};

/* Block device that contains the file system. */
extern struct block* fs_device;

/* Global filesystem lock. */
extern struct lock fs_lock;

void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(const char* name, off_t initial_size);
struct file* filesys_open(const char* name);
bool filesys_remove(const char* name);

struct dir* get_last_dir(const char* path);
bool create_helper(const char* path, off_t initial_size, bool is_dir);
struct inode* open_helper(struct dir* dir, const char* path, uint32_t index);
bool mkdir_helper(char* path, struct dir** dir, char** file_name);

#endif /* filesys/filesys.h */
