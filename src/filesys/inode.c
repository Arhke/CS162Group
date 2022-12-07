#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }


/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
    ASSERT(inode != NULL);
        if (pos < inode->data.length)
            return inode->data.start + pos / BLOCK_SECTOR_SIZE;
        else
            return -1;

    /*
    ASSERT(inode != NULL);
    if (pos < inode->data.length) {
        off_t index = pos / BLOCK_SECTOR_SIZE;
        block_sector_t sector;
        off_t base = 0;
        off_t limit = 0;

        limit += 122;
        if (index < limit) {
            return inode->data.direct_pointers[index];
        }
        base = limit;


        limit += 128;
        if (index < limit) {
            block_sector_t indirect_block;
            return indirect_block;
        }
        
        return sector;
    }
    else
        return -1;
    */
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock open_inodes_lock;

/* Initializes the inode module. */
void inode_init(void) {
    list_init(&open_inodes);
    lock_init(&open_inodes_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(char* absolutePath, block_sector_t sector, off_t length) {
    struct inode_disk* disk_inode = NULL;
    bool success = false;

    ASSERT(length >= 0);

    /* If this assertion fails, the inode structure is not exactly
        one sector in size, and you should fix that. */
    ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    int cache_block_index;
    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode != NULL) {
        size_t sectors = bytes_to_sectors(length);
        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;
        disk_inode->is_dir = false;
        disk_inode->name = calloc(strlen(absolutePath)+1, 1);
        strlcpy(disk_inode->name, absolutePath, strlen(absolutePath)+1);

        lock_acquire(&free_map_lock);
        if (free_map_allocate(sectors, &disk_inode->start)) {
            lock_release(&free_map_lock);

            lock_acquire(&buffer_cache_lock);
                cache_block_index = buffer_cache_find_or_allocate_sector(sector);
                memcpy(buffer_cache_blocks[cache_block_index], disk_inode, BLOCK_SECTOR_SIZE);
                dirty_bits |= (1 << cache_block_index);
            lock_release(&buffer_cache_lock);

            if (sectors > 0) {
                for (size_t i = 0; i < sectors; i++) {
                    lock_acquire(&buffer_cache_lock);
                        cache_block_index = buffer_cache_find_or_allocate_sector(disk_inode->start + i);
                        memset(buffer_cache_blocks[cache_block_index], 0, BLOCK_SECTOR_SIZE);
                        dirty_bits |= (1 << cache_block_index);
                    lock_release(&buffer_cache_lock);
                }
            }
            success = true;
        } else {
            lock_release(&free_map_lock);
        }


        free(disk_inode);
    }
    return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
    struct list_elem* e;
    struct inode* inode;

    /* Check whether this inode is already open. */
    lock_acquire(&open_inodes_lock);
    for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
        inode = list_entry(e, struct inode, elem);
        if (inode->sector == sector) {
            inode_reopen(inode);

            lock_release(&open_inodes_lock);
            return inode;
        }
    }

    /* Allocate memory. */
    inode = malloc(sizeof *inode);
    if (inode == NULL) {
        lock_release(&open_inodes_lock);
        return NULL;
    }

    /* Initialize. */
    list_push_front(&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    lock_init(&inode->access_lock);
    lock_init(&inode->directory_lock);

    lock_acquire(&buffer_cache_lock);
        void *cache_block = buffer_cache_blocks[buffer_cache_get_sector(inode->sector)];
        memcpy(&inode->data, cache_block, BLOCK_SECTOR_SIZE);
    lock_release(&buffer_cache_lock);

    lock_release(&open_inodes_lock);
    return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
    if (inode != NULL)
        lock_acquire(&inode->access_lock);
            inode->open_cnt++;
        lock_release(&inode->access_lock);
    return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) {
    return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
    /* Ignore null pointer. */
    if (inode == NULL)
        return;

    /* Release resources if this was the last opener. */
    lock_acquire(&inode->access_lock);
    if (--inode->open_cnt == 0) {
        /* Remove from inode list and release lock. */
        lock_acquire(&open_inodes_lock);
            list_remove(&inode->elem);
        lock_release(&open_inodes_lock);

        /* Deallocate blocks if removed. */
        if (inode->removed) {
            lock_acquire(&free_map_lock);
                free_map_release(inode->sector, 1);
                free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
            lock_release(&free_map_lock);
            free(inode->data.name);

            lock_acquire(&buffer_cache_lock);
                int cache_block_index = buffer_cache_find_sector(inode->sector);
                if (cache_block_index != -1) {
                    valid_bits &= ~(1 << cache_block_index);
                }
            lock_release(&buffer_cache_lock);
        } else {
            lock_acquire(&buffer_cache_lock);
                int cache_block_index = buffer_cache_find_or_allocate_sector(inode->sector);
                memcpy(buffer_cache_blocks[cache_block_index], &inode->data, BLOCK_SECTOR_SIZE);
                dirty_bits |= (1 << cache_block_index);
            lock_release(&buffer_cache_lock);

            // Maybe flush the buffer cache here but don't know
            
            /* for (int i = 0; i < bytes_to_sectors(inode->data.length); i++) {
                lock_acquire(&buffer_cache_lock);
                    int cache_block_index = buffer_cache_find_or_allocate_sector(inode->data.start + i);
                    memcpy(buffer_cache_blocks[cache_block_index], &inode->data, BLOCK_SECTOR_SIZE);
                    dirty_bits |= (1 << cache_block_index);
                lock_release(&buffer_cache_lock);
            } */
        }


        free(inode);
    } else {
        lock_release(&inode->access_lock);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
bool inode_remove(struct inode* inode) {
    ASSERT(inode != NULL);
    if(strcmp(inode->data.name, "/0/0/2") == 0){
        char *a;
        int b = 2;
    }
    if(strcmp(inode->data.name, "/0/0") == 0){
        char *a;
        int b = 2;
    }
    lock_acquire(&inode->access_lock);
    // char absolutePath[strlen(inode->data.name)+2];
    // snprintf(absolutePath, strlen(inode->data.name)+2, "%s/", inode->data.name)
    struct list_elem* e;
    char* path = inode->data.name;
    
    for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)){
        char* pathCMP = list_entry(e, struct inode, elem)->data.name;
        if (strlen(path) >= strlen(pathCMP)) {
            continue;
        } else{
            for (uint32_t i = 0; i < strlen(path); i++) {
                if(path[i] != pathCMP[i]){
                    goto outerLoop;
                }
            }
            if (pathCMP[strlen(path)] == '/') {
                lock_release(&inode->access_lock);
                return false;
                // return;
            }
        }
        outerLoop:;
    }
    inode->removed = true;
    lock_release(&inode->access_lock);
    return true;
    // return;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
    uint8_t* buffer = buffer_;
    off_t bytes_read = 0;

    lock_acquire(&inode->access_lock);
        while (size > 0) {
            /* Disk sector to read, starting byte offset within sector. */
            block_sector_t sector_idx = byte_to_sector(inode, offset);
            int sector_ofs = offset % BLOCK_SECTOR_SIZE;

            /* Bytes left in inode, bytes left in sector, lesser of the two. */
            off_t inode_left = inode->data.length - offset;
            int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
            int min_left = inode_left < sector_left ? inode_left : sector_left;

            /* Number of bytes to actually copy out of this sector. */
            int chunk_size = size < min_left ? size : min_left;
            if (chunk_size <= 0)
                break;

            lock_acquire(&buffer_cache_lock);
                void *cache_block = buffer_cache_blocks[buffer_cache_get_sector(sector_idx)];
                memcpy(buffer + bytes_read, cache_block + sector_ofs, chunk_size);
            lock_release(&buffer_cache_lock);

            /* Advance. */
            size -= chunk_size;
            offset += chunk_size;
            bytes_read += chunk_size;
        }
    lock_release(&inode->access_lock);

    return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
    const uint8_t* buffer = buffer_;
    off_t bytes_written = 0;

    lock_acquire(&inode->access_lock);
        if (inode->deny_write_cnt) {
            lock_release(&inode->access_lock);
            return 0;
        }

        while (size > 0) {
            /* Sector to write, starting byte offset within sector. */
            block_sector_t sector_idx = byte_to_sector(inode, offset);
            int sector_ofs = offset % BLOCK_SECTOR_SIZE;

            /* Bytes left in inode, bytes left in sector, lesser of the two. */
            off_t inode_left = inode->data.length - offset;
            int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
            int min_left = inode_left < sector_left ? inode_left : sector_left;

            /* Number of bytes to actually write into this sector. */
            int chunk_size = size < min_left ? size : min_left;
            if (chunk_size <= 0)
                break;
            
            int cache_block_index;
            lock_acquire(&buffer_cache_lock);
                if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
                    /* Write full sector directly to disk. */
                    cache_block_index = buffer_cache_find_or_allocate_sector(sector_idx);
                    memcpy(buffer_cache_blocks[cache_block_index], buffer + bytes_written, BLOCK_SECTOR_SIZE);
                } else {
                    /* If the sector contains data before or after the chunk
                            we're writing, then we need to read in the sector
                            first.  Otherwise we start with a sector of all zeros. */
                    if (sector_ofs > 0 || chunk_size < sector_left) {
                        cache_block_index = buffer_cache_get_sector(sector_idx);
                    } else {
                        cache_block_index = buffer_cache_find_or_allocate_sector(sector_idx);
                        memset(buffer_cache_blocks[cache_block_index], 0, BLOCK_SECTOR_SIZE);
                    }
                    memcpy(buffer_cache_blocks[cache_block_index] + sector_ofs, buffer + bytes_written, chunk_size);
                }
                dirty_bits |= (1 << cache_block_index);
            lock_release(&buffer_cache_lock);

            /* Advance. */
            size -= chunk_size;
            offset += chunk_size;
            bytes_written += chunk_size;
        }
    lock_release(&inode->access_lock);

    return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
    lock_acquire(&inode->access_lock);
        inode->deny_write_cnt++;
        ASSERT(inode->deny_write_cnt <= inode->open_cnt);
    lock_release(&inode->access_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
    lock_acquire(&inode->access_lock);
        ASSERT(inode->deny_write_cnt > 0);
        ASSERT(inode->deny_write_cnt <= inode->open_cnt);
        inode->deny_write_cnt--;
    lock_release(&inode->access_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {
    off_t result;
    lock_acquire(&inode->access_lock);
        result = inode->data.length;
    lock_release(&inode->access_lock);
    return result;
}

bool inode_resize(struct inode_disk* id, off_t size);

bool inode_resize(struct inode_disk* id, off_t size) {
    if (size < 0) {
        return false;
    }

    for (int i = 0; i < 122; i++) {
        if (size <= BLOCK_SECTOR_SIZE * i && id->direct_pointers[i] != 0) {
            free_map_release(id->direct_pointers[i], 1);
            id->direct_pointers[i] = 0;
        } else if (size > BLOCK_SECTOR_SIZE * i && id->direct_pointers[i] == 0) {
            free_map_allocate(1, &id->direct_pointers[i]);
            if (id->direct_pointers[i] == 0) {
                inode_resize(id, id->length);
                return false;
            }
        }
    }

    if (id->indirect_pointer == 0 && size <= 12 * BLOCK_SECTOR_SIZE) {
        id->length = size;
        return true;
    }
    block_sector_t buffer[128];
    memset(buffer, 0, 512);
    if (id->indirect_pointer == 0) {
        free_map_allocate(1, &id->indirect_pointer);
        if (id->indirect_pointer == 0) {
            inode_resize(id, id->length);
            return false;
        }
    } else {
        /* implement block_read */
    }

    for (int i = 0; i < 128; i++) {
        if (size <= (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
            free_map_release(buffer[i], 1);
            buffer[i] = 0;
        } else if (size > (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
            free_map_allocate(1, &buffer[i]);
            if (buffer[i] == 0) {
                return false;
            }
        }
    }
    if (size <= 12 * BLOCK_SECTOR_SIZE) {
        free_map_release(id->indirect_pointer, 1);
        id->indirect_pointer = 0;
    } else {
        /* implement block_write */
    }
    id->length = size;

    return true;
}

/* Returns true if an inode is a directory, or false if it's a file */
bool inode_is_dir(struct inode* inode) {
  return inode->data.is_dir;
}
