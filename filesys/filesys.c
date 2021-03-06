#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format(void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void filesys_init(bool format)
{
    filesys_disk = disk_get(0, 1);
    if (filesys_disk == NULL)
        PANIC("hd0:1 (hdb) not present, file system initialization failed");

    inode_init();

#ifdef EFILESYS
    fat_init();

    if (format)
        do_format();

    fat_open();

    //! ADD : 루트디렉토리 설정
    thread_current()->cur_dir = dir_open_root();
#else
    /* Original FS */
    free_map_init();

    if (format)
        do_format();

    free_map_open();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void filesys_done(void)
{
    /* Original FS */
#ifdef EFILESYS
    fat_close();
#else
    free_map_close();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size)
{
    //! ADD
    bool success = false;
#ifdef EFILESYS

    //! 여기 수정 필요
    // struct dir *dir = dir_open_root();
    //!
    /* name의파일경로를cp_name에복사*/
    char* cp_name = (char *)malloc(strlen(name) + 1);
    strlcpy(cp_name, name, strlen(name) + 1);

    /* cp_name의경로분석*/
    char* file_name;
    struct dir* dir = parse_path(cp_name, file_name);
    free(cp_name);

    cluster_t inode_cluster = fat_create_chain(0);
    // printf("inode_cluster :; %d\n", inode_cluster);
    // disk_sector_t inode_sector = cluster_to_sector(inode_cluster);
    success = (dir != NULL
               //! ADD : is_dir 인자 추가 && name -> file_name
               && inode_create(inode_cluster, initial_size, 0) && dir_add(dir, file_name, inode_cluster));
    if (!success && inode_cluster != 0)
        fat_remove_chain(inode_cluster, 0);
    dir_close(dir);
    // printf("success : %d\n", success);
    return success;

#else

    disk_sector_t inode_sector = 0;
    struct dir *dir = dir_open_root();
    success = (dir != NULL && free_map_allocate(1, &inode_sector) && inode_create(inode_sector, initial_size, 0) && dir_add(dir, name, inode_sector));
    if (!success && inode_sector != 0)
        free_map_release(inode_sector, 1);
    dir_close(dir);

    return success;

#endif
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name)
{
    #ifdef EFILESYS

    // struct dir *dir = dir_open_root();

    /* name의파일경로를cp_name에복사*/
    char* cp_name = (char *)malloc(strlen(name) + 1);
    strlcpy(cp_name, name, strlen(name) + 1);

    /* cp_name의경로분석*/
    char* file_name;
    struct dir* dir = parse_path(cp_name, file_name);
    free(cp_name);

    struct inode *inode = NULL;

    if (dir != NULL)
        dir_lookup(dir, file_name, &inode);
    dir_close(dir);

    return file_open(inode);    

    #else

    struct dir *dir = dir_open_root();
    struct inode *inode = NULL;

    if (dir != NULL)
        dir_lookup(dir, name, &inode);
    dir_close(dir);

    return file_open(inode);

    #endif
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name)
{
    #ifdef EFILESYS

    // struct dir *dir = dir_open_root();

    /* name의파일경로를cp_name에복사*/
    char* cp_name = (char *)malloc(strlen(name) + 1);
    strlcpy(cp_name, name, strlen(name) + 1);

    /* cp_name의경로분석*/
    char* file_name;
    struct dir* dir = parse_path(cp_name, file_name);
    free(cp_name);

    bool success = dir != NULL && dir_remove(dir, file_name);
    dir_close(dir);

    return success;

    #else

    struct dir *dir = dir_open_root();
    bool success = dir != NULL && dir_remove(dir, name);
    dir_close(dir);

    return success;

    #endif
}

//! ADD
bool filesys_create_dir(const char* name) {

    /* name의파일경로를cp_name에복사*/
    char* cp_name = (char *)malloc(strlen(name) + 1);
    strlcpy(cp_name, name, strlen(name) + 1);

    /* name 경로분석*/
    char* file_name;
    struct dir* dir = parse_path(cp_name, file_name);
    free(cp_name);

    /* bitmap에서inodesector번호할당*/
    cluster_t inode_cluster = fat_create_chain(0);

    struct inode *sub_dir_inode;
    struct dir *sub_dir;

    /* 할당받은sector에file_name의디렉터리생성*/
    /* 디렉터리엔트리에file_name의엔트리추가*/
    /* 디렉터리엔트리에‘.’, ‘..’ 파일의엔트리추가*/
    bool success = (dir != NULL
               //! ADD : ".", ".." 추가
               && dir_create(inode_cluster, 16)
               && dir_add(dir, file_name, inode_cluster)
               && dir_lookup(dir, file_name, &sub_dir_inode)
               && dir_add(sub_dir = dir_open(sub_dir_inode), ".", inode_cluster)
               && dir_add(sub_dir, "..", inode_get_inumber(dir_get_inode(dir))));

    if (!success && inode_cluster != 0)
        fat_remove_chain(inode_cluster, 0);
    dir_close(sub_dir);
    dir_close(dir);
    // printf("success : %d\n", success);
    return success;
}

//! ADD
struct dir *parse_path(char *path_name, char *file_name)
{
    struct dir *dir;
    if (path_name == NULL || file_name == NULL)
        return NULL;
    if (strlen(path_name) == 0)
        return NULL;
    /* PATH_NAME의절대/상대경로에따른디렉터리정보저장(구현)*/
    if(path_name[0] == "/")
        dir = dir_open_root();
    else
        dir = dir_reopen(thread_current()->cur_dir);


    char *token, *nextToken, *savePtr;
    token = strtok_r(path_name, "/", &savePtr);
    nextToken = strtok_r(NULL, "/", &savePtr);

    struct inode *inode = malloc (sizeof *inode);
    while (token != NULL && nextToken != NULL)
    {
        /* dir에서token이름의파일을검색하여inode의정보를저장*/
        if (!dir_lookup(dir, token, &inode))
            return NULL;
        
        /* inode가파일일경우NULL 반환*/
        if(!inode_is_dir(inode))
        {
            dir_close(dir);
            return NULL;;
        }
        /* dir의디렉터리정보를메모리에서해지*/
        dir_close(dir);
        /* inode의디렉터리정보를dir에저장*/
        dir = dir_open(inode);
        /* token에검색할경로이름저장*/
        token = nextToken;
        nextToken = strtok_r(NULL, "/", &savePtr);
    }
    /* token의파일이름을file_name에저장*/
    file_name = (char *)malloc(strlen(token) + 1);
    strlcpy (file_name, token, strlen(token) + 1);
    /* dir정보반환*/
    return dir;
}

/* Formats the file system. */
static void
do_format(void)
{
    printf("Formatting file system...");

#ifdef EFILESYS
    /* Create FAT and save it to the disk. */
    fat_create();
    if (!dir_create(ROOT_DIR_SECTOR, 16))
        PANIC("root directory creation failed");
    fat_close();
#else
    free_map_create();
    if (!dir_create(ROOT_DIR_SECTOR, 16))
        PANIC("root directory creation failed");
    free_map_close();
#endif

    printf("done.\n");
}
