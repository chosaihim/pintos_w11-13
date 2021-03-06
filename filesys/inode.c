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

//! ADD 전역변수
#define DIRECT_BLOCK_ENTRIES 123
#define INDIRECT_BLOCK_ENTRIES 128

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

//! ADD
// enum direct_t
// {
//     NORMAL_DIRECT = 0,
//     INDIRECT = 1,
//     DOUBLE_INDIRECT = 2,
//     OUT_LIMIT = 3,
// };

// struct sector_location{
//     enum direct_t directness;
//     off_t index1;
//     off_t index2;
// };

// struct inode_indirect_block{
//     disk_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
// }

// static bool get_disk_inode(const struct inode *inode, struct inode_disk *inode_disk)
// {
//     disk_sector_t on_disk_inode = inode_get_inumber(inode);
// }
//! END

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors (off_t size) {
	return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

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

/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
//^ 데이터를 기록할 디스크 블록 번호를 얻는다
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) {
	ASSERT (inode != NULL);

	//! data length가 EOChain??

	#ifdef EFILESYS

	cluster_t cluster = inode->data.start;
	int sector_ofs = pos / DISK_SECTOR_SIZE;

	while(sector_ofs)
	{
		cluster = fat_get(cluster);
		sector_ofs -= 1;
	}
	// printf("hello~~ my name is cluster %d\n", cluster);
	return cluster_to_sector(cluster);

	#else

	if (pos < inode->data.length)
		return inode->data.start + pos / DISK_SECTOR_SIZE;
	else
		return -1;

	#endif
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length, uint32_t is_dir) {
	#ifdef EFILESYS

	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	// printf("length :: %d\n", length);
	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;

        //! 디렉토리 여부 추가
        disk_inode->is_dir = is_dir;
		
		//! 섹터로 바꿔서 들어왔음
		cluster_t cluster = fat_create_chain(0);
		// printf("아이노드 크리에이트 넘버 :: %d\n", cluster);
		// printf("아이노드 크리에이트 섹터넘버 :: %d\n", sector);
		if(cluster)
		{
			disk_inode->start = cluster;
			disk_write (filesys_disk, cluster_to_sector(sector), disk_inode);

			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;

				// cluster_t cluster = sector_to_cluster(sector);
				// cluster_t next;
				disk_write (filesys_disk, cluster_to_sector(disk_inode->start), zeros);
				for (i = 1; i < sectors; i++){

					// printf("아이노드 크리에이트 !! %d\n", i);
					cluster_t tmp = cluster_to_sector(fat_create_chain(cluster));
					// printf("여기는 tmp :: %d\n", tmp);
					disk_write (filesys_disk, tmp, zeros);

				}
			}
			success = true;
		}
		free (disk_inode);
	}
	return success;

	#else

	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
		if (free_map_allocate (sectors, &disk_inode->start)) {
			disk_write (filesys_disk, sector, disk_inode);
			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;

				for (i = 0; i < sectors; i++) 
					disk_write (filesys_disk, disk_inode->start + i, zeros); 
			}
			success = true; 
		} 
		free (disk_inode);
	}
	return success;

	#endif
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) {
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
			e = list_next (e)) {
		inode = list_entry (e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen (inode);
			return inode; 
		}
	}

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front (&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;

	// inode->data.start = sector;

	// printf("%%%%%%%%%%%%%% inode_sector :: %d\n", inode->sector);
	// printf("오픈 섹터 넘버 :: %d\n", sector);
	disk_read (filesys_disk, cluster_to_sector(inode->sector), &inode->data);
	//! ADD
	// printf("=========== inode_data start :: %d\n", inode->data.start);
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	if (inode != NULL)
		inode->open_cnt++;
	return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode) {
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) {

	#ifdef EFILESYS

	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
			fat_remove_chain (inode->sector, 0);
			fat_remove_chain (inode->data.start, 0); 
		}

		free (inode); 
	}


	#else

	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
			free_map_release (inode->sector, 1);
			free_map_release (inode->data.start,
					bytes_to_sectors (inode->data.length)); 
		}

		free (inode); 
	}

	#endif
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	ASSERT (inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) {

	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	uint8_t *bounce = NULL;

	while (size > 0) {
		/* Disk sector to read, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Read full sector directly into caller's buffer. */
			disk_read (filesys_disk, sector_idx, buffer + bytes_read);
		} else {
			/* Read sector into bounce buffer, then partially copy
			 * into caller's buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}
			disk_read (filesys_disk, sector_idx, bounce);
			memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}
	free (bounce);

	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
		off_t offset) {

	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;
	uint8_t *bounce = NULL;

	if (inode->deny_write_cnt)
		return 0;

	// printf("사이즈 :: %d\n", size);
	// printf("bytes_written %d\n", bytes_written);

	// disk_sector_t sector_idx;
	// cluster_t tmp;
	if (inode_length(inode) < offset + size)
	{
		// printf("필요한 섹터 수 :: %d\n", bytes_to_sectors (size));
		// printf("이미 있는 섹터 수 :: %d\n", bytes_to_sectors(inode_length(inode)));

		size_t sectors = bytes_to_sectors (offset + size) - bytes_to_sectors(inode_length(inode));
		// disk_inode->magic = INODE_MAGIC;
		// inode_create(inode->data.start, size);
		// printf("아이노드 데이타 스타트 :: %d\n", inode->data.start);
		if (sectors > 0)
		{
			static char zeros[DISK_SECTOR_SIZE];
			cluster_t tmp;
			for (int i = 0; i < sectors; i++)
			{
				tmp = fat_create_chain(inode->data.start);
				// printf("클러스터 탬프 :: %d\n", tmp);
				disk_write(filesys_disk, cluster_to_sector(tmp), zeros);
			}
		}
		// printf("before 아이노드 사이즈 :: %d\n", inode->data.length);
		inode->data.length = offset + size;
		// printf("after 아이노드 사이즈 :: %d\n", inode->data.length);
		// inode = inode_open(sector_idx);
		disk_write(filesys_disk, cluster_to_sector(inode->sector), &inode->data);
	}
	// printf("아이노드 렝스 :: %d\n", inode_length(inode));
	// disk_read (filesys_disk, cluster_to_sector(inode->sector), &inode->data);

	while (size > 0) {
		// disk_sector_t sector_idx;
		/* Sector to write, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
        //^ 데이터를 기록할 디스크 블록 내부의 오프셋
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		// printf("섹터 인덱스 :: %d\n", sector_idx);
		// printf("섹터 오프셋 :: %d\n", sector_ofs);


		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;
		// printf("아이노드 left :: %d\n", inode_left);
		// printf("섹터 left :: %d\n", sector_left);
		// printf("민 left :: %d\n", min_left);

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < min_left ? size : min_left;
		// printf("청크사이즈 :: %d\n", chunk_size);
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			//^ Write full sector directly to disk. */
			disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
		} else {
			//^ We need a bounce buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}

			/* If the sector contains data before or after the chunk
			   we're writing, then we need to read in the sector
			   first.  Otherwise we start with a sector of all zeros. */
			if (sector_ofs > 0 || chunk_size < sector_left){
				disk_read (filesys_disk, sector_idx, bounce);
			}
			else
				memset (bounce, 0, DISK_SECTOR_SIZE);
			memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
			disk_write (filesys_disk, sector_idx, bounce); 
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
		// printf("사이즈 :: %d\n", size);
	}
	free (bounce);
	// printf("bytes_written %d\n", bytes_written);

	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
	return inode->data.length;
}

//! ADD
bool inode_is_dir(const struct inode* inode) {
    bool result;
    /* inode_disk자료구조를메모리에할당*/
    struct inode_disk *disk_inode = calloc (1, sizeof *disk_inode);
    /* in-memory inode의on-disk inode를읽어inode_disk에저장*/
    disk_read(filesys_disk, cluster_to_sector(inode->sector), disk_inode);
    /* on-disk inode의is_dir을result에저장하여반환*/
    result = disk_inode->is_dir;
    free(disk_inode);
    
    return result;
}