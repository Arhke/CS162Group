#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buffer.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "lib/kernel/list.h"
#include <stdlib.h>



/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);
static int get_next_part(char part[NAME_MAX + 1], const char** srcp);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
    buffer_cache_init();

    fs_device = block_get_role(BLOCK_FILESYS);
    if (fs_device == NULL)
        PANIC("No file system device found, can't initialize file system.");

    inode_init();
    free_map_init();

    if (format)
        do_format();

    free_map_open();

    /* Set cwd for initial process to the filesystem root */
    struct process* pcb = thread_current()->pcb->cwd = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
    free_map_close();
    buffer_cache_flush();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* path, off_t initial_size) {
    if (*path == 0) {
        return false;
    } else {
        return create_helper(path, initial_size, false);
    }
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open(const char* name) {
    return file_open(open_helper(name));
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
    char* file_to_remove;
    struct dir* dir;
    bool success = mkdir_helper((char*) name, &dir, &file_to_remove);
    if (!success)
        return false;

    /* Disallow if dir has entries other than . and .. */
    struct inode* inode;
    if (dir_lookup(dir, file_to_remove, &inode)) {
        if (inode_is_dir(inode)) {
            struct dir* dir_to_remove = dir_open(inode);

            char dir_name[NAME_MAX + 1];
            while (dir_readdir(dir_to_remove, dir_name)) {
                if (strcmp(dir_name, ".") && strcmp(dir_name, "..")) {
                    /* dir has something in it besides . and .., block remove */
                    dir_close(dir_to_remove);
                    dir_close(dir);
                    return false;
                }
            }

            dir_close(dir_to_remove);
        } else {
            inode_close(inode);
        }
    }


    success = dir != NULL && dir_remove(dir, file_to_remove);
    dir_close(dir);

    return success;
}

/* Formats the file system. */
static void do_format(void) {
    printf("Formatting file system...");
    free_map_create();
    if (!dir_create("", 16))
        PANIC("root directory creation failed");
    free_map_close();
    printf("done.\n");
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
    const char* src = *srcp;
    char* dst = part;

    /* Skip leading slashes.  If it's all slashes, we're done. */
    while (*src == '/')
        src++;
    if (*src == '\0')
        return 0;

    /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
    while (*src != '/' && *src != '\0') {
        if (dst < part + NAME_MAX)
            *dst++ = *src;
        else
            return -1;
        src++;
    }
    *dst = '\0';

    /* Advance source pointer. */
    *srcp = src;
    return 1;
}

struct dir* get_last_dir(const char* path) {
    struct dir* dir;
    if (path[0] == '/') {
        dir = dir_open_root();
    } else {
        dir = dir_reopen(thread_current()->pcb->cwd);
    }
    char part[NAME_MAX + 1];
    int valid = 0;
    struct inode* inode;
    while ((valid = get_next_part(part, &path))) {
        if (dir_lookup(dir, part, &inode)) {
            dir_close(dir);
            dir = dir_open(inode);
        } else {
            /* Path doesn't exist, close current dir and return NULL */
            dir_close(dir);
            return NULL;
        }
    }

    if (valid == -1) {
        dir_close(dir);
        return NULL;
    }

    return dir;
}

bool create_helper(const char* path, off_t initial_size, bool is_dir) {
    struct dir *dir;
    char *file_name;
    bool success = false;
    if (mkdir_helper(path, &dir, &file_name) && !dir->inode->removed) {
        block_sector_t inode_sector;
        if (free_map_allocate(1, &inode_sector)) {
            if ((success = inode_create(inode_sector, initial_size, is_dir) && dir_add(dir, file_name, inode_sector))) {
                struct inode *inode = inode_open(inode_sector);
                if (is_dir) {
                    struct dir *new_dir = dir_open(inode);
                    dir_add(new_dir, ".", inode_sector);
                    dir_add(new_dir, "..", dir->inode->sector);
                    dir_close(new_dir);
                }
            } else {
                free_map_release(inode_sector, 1);
            }
        }
        dir_close(dir);
    }
    return success;
}

struct inode* open_helper(const char* path) {
    struct dir *dir;
    char *file_name;

    struct inode *inode = NULL;
    if (mkdir_helper(path, &dir, &file_name) && !dir->inode->removed) {
        dir_lookup(dir, file_name, &inode);
        dir_close(dir);
    }
    return inode;
}

bool mkdir_helper(char* path, struct dir** dir, char** file_name) {
    int last_slash = strlen(path);
    while (--last_slash >= 0 && path[last_slash] != '/');
    if (last_slash == -1) {
        *file_name = path;
        *dir = dir_reopen(thread_current()->pcb->cwd);
        return true;
    } else if (last_slash == 0) {
        *file_name = path + 1;
        *dir = dir_open_root();
        return true;
    } else {
        char *path_cpy = malloc(strlen(path) + 1);
        memcpy(path_cpy, path, strlen(path) + 1);

        path_cpy[last_slash] = 0;
        *file_name = path + last_slash + 1;
        bool success = (*dir = get_last_dir(path_cpy)) != NULL;
        free(path_cpy);
        return success;
    }
}