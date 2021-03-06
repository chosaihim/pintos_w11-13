#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/disk.h"
//! ADD
#include "filesys/fat.h"
#include "lib/kernel/list.h"

struct bitmap;

void inode_init (void);
bool inode_create (disk_sector_t, off_t, uint32_t);
struct inode *inode_open (disk_sector_t);
struct inode *inode_reopen (struct inode *);
disk_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

//! ADD
bool inode_is_dir(const struct inode* inode);

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
    //! 제거
	disk_sector_t start;                /* First data sector. */
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
    //! ADD

    uint32_t is_dir;    /* 디렉토리 구분 */

    //! END

    //^ 멤버 추가시마다 512바이트 맞추기
	uint32_t unused[124];               /* Not used. */
    //! ADD

    // disk_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES];
    // disk_sector_t indirect_block_sec;
    // disk_sector_t double_indirect_block_sec;
    //! END
};

/* In-memory inode. */
struct inode {
	struct list_elem elem;              /* Element in inode list. */
	disk_sector_t sector;               /* Sector number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    //! ADD
	// struct lock extend_lock;
    //! 제거
	struct inode_disk data;             /* Inode content. */
};


#endif /* filesys/inode.h */
