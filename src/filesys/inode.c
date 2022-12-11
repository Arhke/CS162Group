#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/buffer.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_DIRECT_POINTERS 122
#define INDIRECT_BLOCK_SIZE 128

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }


/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode_disk *inode_data, off_t pos) {
    ASSERT(inode_data != NULL);
    if (0 <= pos && pos < inode_data->length) {
        off_t index = pos / BLOCK_SECTOR_SIZE;
        off_t base = 0;
        off_t limit = 0;
        block_sector_t sector;

        /* Direct Blocks */
        limit += NUM_DIRECT_POINTERS;
        if (index < limit) {
            sector = inode_data->direct_pointers[index];
            return sector;
        }
        base = limit;

        /* Indirect Blocks */
        limit += INDIRECT_BLOCK_SIZE;
        if (index < limit) {
            struct indirect_block* block = calloc(1, sizeof(struct indirect_block));
            buffer_cache_read(inode_data->indirect_pointer, block);

            sector = block->blocks[index - base];
            free(block);

            return sector;
        }
        base = limit;

        /* Doubly-Indirect Blocks */
        limit += INDIRECT_BLOCK_SIZE * INDIRECT_BLOCK_SIZE;
        if (index < limit) {
            off_t first_index = (index - base) / INDIRECT_BLOCK_SIZE;
            off_t second_index = (index - base) % INDIRECT_BLOCK_SIZE;

            struct indirect_block* block = calloc(1, sizeof(struct indirect_block));

            buffer_cache_read(inode_data->doubly_indirect_pointer, block);
            buffer_cache_read(block->blocks[first_index], block);

            sector = block->blocks[second_index];
            free(block);

            return sector;
        }
    }
    return -1;
}


/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
struct list open_inodes;
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
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {
    struct inode_disk* disk_inode = NULL;
    bool success = false;

    ASSERT(length >= 0);

    /* If this assertion fails, the inode structure is not exactly
        one sector in size, and you should fix that. */
    ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    int cache_block_index;
    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode != NULL) {
        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;
        disk_inode->is_dir = is_dir;

        if (inode_resize(disk_inode, disk_inode->length)) {
            buffer_cache_write(sector, disk_inode);
            success = true;
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
            free_map_release(inode->sector, 1);
            inode_deallocate(inode);

            buffer_cache_invalidate(inode->sector);
        }


        free(inode);
    } else {
        lock_release(&inode->access_lock);
    }
}


/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
    ASSERT(inode != NULL);
    lock_acquire(&inode->access_lock);
        inode->removed = true;
    lock_release(&inode->access_lock);
}


/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
    uint8_t* buffer = buffer_;
    off_t bytes_read = 0;

    lock_acquire(&inode->access_lock);
        struct inode_disk *inode_data = inode_read_data(inode);

        while (size > 0) {
            /* Disk sector to read, starting byte offset within sector. */
            block_sector_t sector_idx = byte_to_sector(inode_data, offset);
            int sector_ofs = offset % BLOCK_SECTOR_SIZE;

            /* Bytes left in inode, bytes left in sector, lesser of the two. */
            off_t inode_left = inode_data->length - offset;
            int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
            int min_left = inode_left < sector_left ? inode_left : sector_left;

            /* Number of bytes to actually copy out of this sector. */
            int chunk_size = size < min_left ? size : min_left;
            if (chunk_size <= 0)
                break;

            buffer_cache_read_chunk(sector_idx, sector_ofs, chunk_size, buffer + bytes_read);

            /* Advance. */
            size -= chunk_size;
            offset += chunk_size;
            bytes_read += chunk_size;
        }

        free(inode_data);
    lock_release(&inode->access_lock);

    return bytes_read;
}


/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs. */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
    const uint8_t* buffer = buffer_;
    off_t bytes_written = 0;

    lock_acquire(&inode->access_lock);
        if (inode->deny_write_cnt) {
            lock_release(&inode->access_lock);
            return 0;
        }

        struct inode_disk *inode_data = inode_read_data(inode);

        if (byte_to_sector(inode_data, offset + size - 1) == (block_sector_t) -1) {
            if (!inode_resize(inode_data, offset + size)) {
                return 0;
            }

            inode_data->length = offset + size;
            inode_write_data(inode, inode_data);
        }

        while (size > 0) {
            /* Sector to write, starting byte offset within sector. */
            block_sector_t sector_idx = byte_to_sector(inode_data, offset);
            int sector_ofs = offset % BLOCK_SECTOR_SIZE;

            /* Bytes left in inode, bytes left in sector, lesser of the two. */
            off_t inode_left = inode_data->length - offset;
            int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
            int min_left = inode_left < sector_left ? inode_left : sector_left;


            /* Number of bytes to actually write into this sector. */
            int chunk_size = size < min_left ? size : min_left;
            if (chunk_size <= 0)
                break;
            
            if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
                /* Write full sector directly to disk. */
                buffer_cache_write(sector_idx, buffer + bytes_written);
            } else {
                /* If the sector contains data before or after the chunk
                        we're writing, then we need to read in the sector
                        first.  Otherwise we start with a sector of all zeros. */
                buffer_cache_write_chunk(sector_idx, sector_ofs, chunk_size, buffer + bytes_written);
            }

            /* Advance. */
            size -= chunk_size;
            offset += chunk_size;
            bytes_written += chunk_size;
        }

        free(inode_data);
    lock_release(&inode->access_lock);

    return bytes_written;
}


struct inode_disk *inode_read_data(struct inode *inode) {
    struct inode_disk *inode_data = malloc(sizeof(struct inode_disk));
    buffer_cache_read(inode->sector, inode_data);
    return inode_data;
}


void inode_write_data(struct inode *inode, struct inode_disk *inode_data) {
    buffer_cache_write(inode->sector, inode_data);
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
    buffer_cache_read_chunk(inode->sector, offsetof(struct inode_disk, length), sizeof(off_t), &result);
    return result;
}


/* Allows for file growth, like Cho-Gath! */
bool inode_resize(struct inode_disk* id, off_t size) {
    if (size < 0) {
        return false;
    }

    /* Direct Pointers */
    for (int i = 0; i < NUM_DIRECT_POINTERS; i++) {
        if (size <= BLOCK_SECTOR_SIZE * i && id->direct_pointers[i] != 0) {
            free_map_release(id->direct_pointers[i], 1);
            
            id->direct_pointers[i] = 0;
        } else if (size > BLOCK_SECTOR_SIZE * i && id->direct_pointers[i] == 0) {
            free_map_allocate(1, &id->direct_pointers[i]);

            /* Return false if unable to allocate sector */
            if (id->direct_pointers[i] == 0) {
                inode_resize(id, id->length);
                return false;
            }

            buffer_cache_zero(id->direct_pointers[i]);
        }
    }
    
    /* Check if indirect pointers are needed */
    if (id->indirect_pointer == 0 && size <= NUM_DIRECT_POINTERS * BLOCK_SECTOR_SIZE) {
        id->length = size;
        return true;
    }

    /* Indirect Pointers */
    block_sector_t* buffer = calloc(1, BLOCK_SECTOR_SIZE);
    if (id->indirect_pointer == 0) {
        /* Allocate indirect block */
        free_map_allocate(1, &id->indirect_pointer);

        /* Return false if unable to allocate sector */
        if (id->indirect_pointer == 0) {
            inode_resize(id, id->length);
            return false;
        }

        buffer_cache_zero(id->indirect_pointer);
    } else {
        /* Read in indirect block */
        buffer_cache_read(id->indirect_pointer, buffer);
    }

    for (int i = 0; i < INDIRECT_BLOCK_SIZE; i++) {
        if (size <= (NUM_DIRECT_POINTERS + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
            free_map_release(buffer[i], 1);
            buffer[i] = 0;
        } else if (size > (NUM_DIRECT_POINTERS + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
            free_map_allocate(1, &buffer[i]);

            /* Return false if unable to allocate sector */
            if (buffer[i] == 0) {
                inode_resize(id, id->length);
                return false;
            }

            buffer_cache_zero(buffer[i]);
        }
    }
    if (size <= NUM_DIRECT_POINTERS * BLOCK_SECTOR_SIZE) {
        free_map_release(id->indirect_pointer, 1);
        id->indirect_pointer = 0;
    } else {
        buffer_cache_write(id->indirect_pointer, buffer);
    }
    
    /* Check if doubly-indirect pointers are needed */
    if (id->doubly_indirect_pointer == 0 && size <= (NUM_DIRECT_POINTERS + INDIRECT_BLOCK_SIZE) * BLOCK_SECTOR_SIZE) {
        id->length = size;
        free(buffer);
        return true;
    }

    /* Doubly-Indirect Pointers */
    buffer = calloc(1, BLOCK_SECTOR_SIZE);
    if (id->doubly_indirect_pointer == 0) {
        /* Allocate doubly-indirect block */
        free_map_allocate(1, &id->doubly_indirect_pointer);

        /* Return false if unable to allocate sector */
        if (id->doubly_indirect_pointer == 0) {
            inode_resize(id, id->length);
            return false;
        }
        
        buffer_cache_zero(id->doubly_indirect_pointer);
    } else {
        /* Read in doubly-indirect block */
        buffer_cache_read(id->doubly_indirect_pointer, buffer);
    }

    for (int i = 0; i < INDIRECT_BLOCK_SIZE; i++) {
        if (size <= (NUM_DIRECT_POINTERS + INDIRECT_BLOCK_SIZE + (i * INDIRECT_BLOCK_SIZE)) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
            free_map_release(buffer[i], 1);
            buffer[i] = 0;
        } else if (size > (NUM_DIRECT_POINTERS + INDIRECT_BLOCK_SIZE + (i * INDIRECT_BLOCK_SIZE)) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
            free_map_allocate(1, &buffer[i]);

            /* Return false if unable to allocate sector */
            if (buffer[i] == 0) {
                inode_resize(id, id->length);
                return false;
            }

            buffer_cache_zero(buffer[i]);
        }
    }
    if (size <= (NUM_DIRECT_POINTERS + INDIRECT_BLOCK_SIZE) * BLOCK_SECTOR_SIZE) {
        free_map_release(id->doubly_indirect_pointer, 1);
        id->doubly_indirect_pointer = 0;
    } else {
        buffer_cache_write(id->doubly_indirect_pointer, buffer);
    }

    /* Indirect Pointers from Doubly-Indirect Block */
    for (int j = 0; j < INDIRECT_BLOCK_SIZE; j++) {
        block_sector_t* second_buffer = calloc(1, BLOCK_SECTOR_SIZE);
        if (buffer[j] == 0) {
            /* Allocate indirect block */
            free_map_allocate(1, &buffer[j]);

            /* Return false if unable to allocate sector */
            if (buffer[j] == 0) {
                inode_resize(id, id->length);
                return false;
            }

            buffer_cache_zero(buffer[j]);
        } else {
            /* Read in indirect block */
            buffer_cache_read(buffer[j], second_buffer);
        }

        for (int i = 0; i < INDIRECT_BLOCK_SIZE; i++) {
            if (size <= (NUM_DIRECT_POINTERS + INDIRECT_BLOCK_SIZE + (INDIRECT_BLOCK_SIZE * j) + i) * BLOCK_SECTOR_SIZE && second_buffer[i] != 0) {
                free_map_release(second_buffer[i], 1);
                second_buffer[i] = 0;
            } else if (size > (NUM_DIRECT_POINTERS + INDIRECT_BLOCK_SIZE + (INDIRECT_BLOCK_SIZE * j) + i) * BLOCK_SECTOR_SIZE && second_buffer[i] == 0) {
                free_map_allocate(1, &second_buffer[i]);

                /* Return false if unable to allocate sector */
                if (second_buffer[i] == 0) {
                    inode_resize(id, id->length);
                    return false;
                }

                buffer_cache_zero(second_buffer[i]);
            }
        }
        if (size <= (NUM_DIRECT_POINTERS + INDIRECT_BLOCK_SIZE + (INDIRECT_BLOCK_SIZE * j)) * BLOCK_SECTOR_SIZE) {
            free_map_release(buffer[j], 1);
            buffer[j] = 0;
        } else {
            buffer_cache_write(buffer[j], second_buffer);
        }
        free(second_buffer);
    }
    free(buffer);

    id->length = size;
    return true;
}


/* Shrinks disk_inode to 0, effectively deallocating it. */
bool inode_deallocate(struct inode *inode) {
    struct inode_disk *inode_data = inode_read_data(inode);
    bool success = inode_resize(inode_data, 0);
    free(inode_data);
    return success;
}


/* Returns true if an inode is a directory, or false if it's a file */
bool inode_is_dir(struct inode* inode) {
    bool is_dir;
    buffer_cache_read_chunk(inode->sector, offsetof(struct inode_disk, is_dir), sizeof(bool), &is_dir);
    return is_dir;
}

