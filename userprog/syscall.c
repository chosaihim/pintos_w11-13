#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/kernel/console.h"
#include "userprog/process.h"
//! ADD: for palloc
#include "threads/palloc.h"
//! ADD : for project 4
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "string.h"
#include "filesys/fat.h"

/* ADD header for page fault */
// #include "userprog/exception.h"
// #include "userprog/process.h"
// #include "threads/init.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* 헤더에 넣으면 오류가 나요 */
struct page *check_address(void *addr);
// void get_frame_argument(void *rsp, int *arg);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
// TODO: Your implementation goes here.

/* rsp 유효성 검증 */
/* 우리는 상한선에서 출발해서 밑으로 쌓았다. */
//! ADD: check_address 주석
// check_address(f->rsp);
#ifdef VM
    thread_current()->rsp_stack = f->rsp;
#endif

    uint64_t number = f->R.rax;
    switch (number)
    {
    case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        exit(f->R.rdi);
        break;
    case SYS_FORK:
        memcpy(&thread_current()->fork_tf, f, sizeof(struct intr_frame));
        f->R.rax = fork(f->R.rdi);
        break;
    case SYS_EXEC:
        //! ADD: insert check_valid_string
        // check_valid_string(f->R.rdi, f->rsp);
        f->R.rax = exec(f->R.rdi);
        break;
    case SYS_WAIT:
        f->R.rax = wait(f->R.rdi);
        break;
    case SYS_CREATE:
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break;
    case SYS_REMOVE:
        f->R.rax = remove(f->R.rdi);
        break;
    case SYS_OPEN:
        //! ADD: insert check_valid_string
        // check_valid_string(f->R.rdi, f->rsp);
        f->R.rax = open(f->R.rdi);
        break;
    case SYS_FILESIZE:
        f->R.rax = filesize(f->R.rdi);
        break;
    case SYS_READ:
        //! ADD: insert check_valid_buffer instead of check_address
        check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_WRITE:
        //! ADD:가 아니라 check_valid_string 만들지 않음(PPT랑 다름)
        check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_SEEK:
        seek(f->R.rdi, f->R.rsi);
        break;
    case SYS_TELL:
        f->R.rax = tell(f->R.rdi);
        break;
    case SYS_CLOSE:
        close(f->R.rdi);
        break;
        //! for VM
    case SYS_MMAP:
        f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
        break;
    case SYS_MUNMAP:
        munmap(f->R.rdi);
        break;
    //! for project 4
    case SYS_ISDIR:
        f->R.rax = is_dir(f->R.rdi);
        break;
    case SYS_CHDIR:
        f->R.rax = sys_chdir(f->R.rdi);
        break;
    case SYS_MKDIR:
        f->R.rax = sys_mkdir(f->R.rdi);
        break;
    case SYS_READDIR:
        f->R.rax = sys_readdir(f->R.rdi, f->R.rsi);
        break;
    case SYS_INUMBER:
        f->R.rax = sys_inumber(f->R.rdi);
        break;
    case SYS_SYMLINK:
        f->R.rax = symlink(f->R.rdi, f->R.rsi);
        break;
    }
    // thread_exit ();
}

/*** It could be dangerous ***/
//! ADD: check_address
struct page *check_address(void *addr)
{
    if (is_kernel_vaddr(addr))
    {
        exit(-1);
    }
    return spt_find_page(&thread_current()->spt, addr);
}
//! END: check_address

// //! ADD: check_valid_buffer
void check_valid_buffer(void *buffer, unsigned size, void *rsp, bool to_write)
{
    /* 인자로받은buffer부터buffer + size까지의크기가한페이지의크기를넘을수도있음*/
    /*check_address를이용해서주소의유저영역여부를검사함과동시에vm_entry구조체를얻음*/
    /* 해당주소에대한vm_entry존재여부와vm_entry의writable멤버가true인지검사*/
    /* 위내용을buffer부터buffer + size까지의주소에포함되는vm_entry들에대해적용*/
    for (int i = 0; i < size; i++)
    {
        struct page *page = check_address(buffer + i);
        if (page == NULL)
            exit(-1);
        if (to_write == true && page->writable == false)
            exit(-1);
    }
}
// //! END: check_valid_buffer

// // //! ADD: check_valid_string
// void check_valid_string(const void *str, void *rsp)
// {
// 	if(check_address(str) == NULL)
//     {
//         exit(-1);
//     }
// }

// //! END: check_valid_string

void halt(void)
{
    power_off();
}
void exit(int status)
{
    struct thread *curr = thread_current();
    curr->exit_status = status;
    curr->is_exit = 1; // be dead by exit syscall!
    // hex_dump(USER_STACK-PGSIZE, (void *)(USER_STACK-PGSIZE), PGSIZE, 1);
    // printf("여기 들어옴??\n");
    printf("%s: exit(%d)\n", thread_current()->name, thread_current()->exit_status);
    thread_exit();
}

pid_t fork(const char *thread_name)
{
    // printf("I'm %d, syscall-fork\n", thread_current()->tid);
    // printf("I'm %d, syscall-fork - fd_table[2] : %p\n", thread_current()->tid, thread_current()->fd_table[2]);
    // printf("I'm %d, syscall-fork - fd_table[3] : %p\n", thread_current()->tid, thread_current()->fd_table[3]);

    return process_fork(thread_name, &thread_current()->fork_tf);
}

int exec(const char *file)
{
    if (process_exec(file))
        return -1;
}

int wait(pid_t pid)
{
    return process_wait(pid);
}
bool create(const char *file, unsigned initial_size)
{
    //! for vine
    if (thread_current()->next_fd > 511)
    {
        return 0;
    }

    if (file)
        return filesys_create(file, initial_size); // ASSERT, dir_add (name!=NULL)
    else
        exit(-1);
}
bool remove(const char *file)
{
    if (file)
        return filesys_remove(file);
    else
        exit(-1);
}
int open(const char *file)
{
    // printf("I'm %d, syscall_open %s\n", thread_current()->tid,file);

    /*thanks filesys_open : NULL, if there isn't */
    if (file)
    {
        struct file *open_file = filesys_open(file);
        if (open_file)
        {
            // printf("만든 파일의 섹터 :: %d\n", open_file->inode->sector);
            return process_add_file(open_file);
        }
        else
            return -1;
    }
    else
        return -1;
}
int filesize(int fd)
{
    struct file *want_length_file = process_get_file(fd);
    int ret = -1;
    if (want_length_file)
    {
        ret = file_length(want_length_file);
        return ret; /* ASSERT (NULL), so we need to branch out */
    }
    else
    {
        return ret;
    }
}
int read(int fd, void *buffer, unsigned length)
{
    lock_acquire(&filesys_lock);
    struct file *target = process_get_file(fd);
    int ret = -1;

    if (target) /* fd == 0 이 었으면, 0을 return 했을 것이다.*/
    {
        if (fd == 0)
        {
            ret = input_getc();
        }
        else
        {
            ret = file_read(target, buffer, length);
        }
    }
    lock_release(&filesys_lock);
    return ret;
}
int write(int fd, const void *buffer, unsigned length)
{
    lock_acquire(&filesys_lock);
    struct file *target = process_get_file(fd);
    int ret = -1;
    if (target)
    {
        if (fd == 1)
        {
            putbuf(buffer, length);
            ret = sizeof(buffer);
        }
        else
        {
            /* 실제로는 inode의 writable이 더 중요하다 !!! */
            if(!inode_is_dir(file_get_inode(target)))
                ret = file_write(target, buffer, (off_t)length);
        }
    }
    lock_release(&filesys_lock);

    return ret;
}
void seek(int fd, unsigned position)
{
    struct file *target = process_get_file(fd);
    file_seek(target, position);
}
unsigned tell(int fd)
{
    struct file *target = process_get_file(fd);
    return file_tell(target);
}
void close(int fd)
{
    process_close_file(fd);
}

//!ADD Memory Mapped Files
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
    // printf(">>>>>> PGSIZE:%d\n",PGSIZE);
    //! mmap-off and mmap-bad-off
    if (offset % PGSIZE != 0)
    {
        return NULL;
    }

    if (pg_round_down(addr) != addr || is_kernel_vaddr(addr) || addr == NULL || (long long)length <= 0)
        // exit(-1);
        return NULL;

    if (fd == 0 || fd == 1)
        exit(-1);

    //! vm_overlap
    if (spt_find_page(&thread_current()->spt, addr))
        return NULL;

    // lock_acquire(&filesys_lock);
    struct file *target = process_get_file(fd);

    if (target == NULL) //? fd가 0이랑 1인 것도 알아서 걸러준다.!!
        return NULL;

    // printf("파일 주소 :: %p\n", target);
    // printf("=============== HELLO =============\n");
    void *ret = do_mmap(addr, length, writable, target, offset);
    // lock_release(&filesys_lock);

    return ret;
}

void munmap(void *addr)
{
    do_munmap(addr);
}
//!END Memory Mapped Files

// TODO =============================== for Project 4 ==========================================
//: file의 directory 여부 판단
bool is_dir(int fd)
{
    struct file *target = process_get_file(fd);
    if (target == NULL)
        return false;

    return inode_is_dir(file_get_inode(target));
}

//: 현재 directory 위치 변경
bool sys_chdir(const char *path_name)
{
    if (path_name == NULL)
        return false;

    /* name의파일경로를cp_name에복사*/
    char *cp_name = (char *)malloc(strlen(path_name) + 1);
    strlcpy(cp_name, path_name, strlen(path_name) + 1);

    struct dir *chdir = NULL;
    /* PATH_NAME의절대/상대경로에따른디렉터리정보저장(구현)*/
    if (cp_name[0] == '/')
    {
        chdir = dir_open_root();
    }
    else
        chdir = dir_reopen(thread_current()->cur_dir);


    /* dir경로를분석하여디렉터리를반환*/
    //! 무조건 경로가 들어올 것이므로, nextToken 불필요
    char *token, *nextToken, *savePtr;
    token = strtok_r(cp_name, "/", &savePtr);

    struct inode *inode = NULL;
    while (token != NULL)
    {
        /* dir에서token이름의파일을검색하여inode의정보를저장*/
        if (!dir_lookup(chdir, token, &inode))
        {
            dir_close(chdir);
            return false;
        }

        /* inode가파일일경우NULL 반환*/
        if (!inode_is_dir(inode))
        {
            dir_close(chdir);
            return false;
        }
        /* dir의디렉터리정보를메모리에서해지*/
        dir_close(chdir);
        
        /* inode의디렉터리정보를dir에저장*/
        chdir = dir_open(inode);

        /* token에검색할경로이름저장*/
        token = strtok_r(NULL, "/", &savePtr);

    }
    /* 스레드의현재작업디렉터리를변경*/
    dir_close(thread_current()->cur_dir);
    thread_current()->cur_dir = chdir;
    free(cp_name);
    return true;
}

//: directory 생성
bool sys_mkdir(const char *dir)
{
    lock_acquire(&filesys_lock);
    bool tmp = filesys_create_dir(dir);

    lock_release(&filesys_lock);
    return tmp;
}

//: directory 내 파일 존재 여부 확인
bool sys_readdir(int fd, char *name)
{
    if (name == NULL)
        return false;

    /* fd리스트에서fd에대한file정보를얻어옴*/
    struct file *target = process_get_file(fd);
    if (target == NULL)
        return false;

    /* fd의file->inode가디렉터리인지검사*/
    if (!inode_is_dir(file_get_inode(target)))
        return false;

    /* p_file을dir자료구조로포인팅*/
    struct dir *p_file = target;
    if(p_file->pos == 0)
        dir_seek(p_file, 2 * sizeof(struct dir_entry)); //! ".", ".." 제외

    /* 디렉터리의엔트에서“.”,”..” 이름을제외한파일이름을name에저장*/
    bool result = dir_readdir(p_file, name);
    // file_close(target);
    // dir_close(p_file);
    return result;
}

//: file의 inode가 기록된 sector 찾기
struct cluster_t *sys_inumber(int fd)
{
    struct file *target = process_get_file(fd);
    if (target == NULL)
        return false;

    return inode_get_inumber(file_get_inode(target));
}

//: 바로가기 file 생성
int symlink (const char *target, const char *linkpath)
{
    //! SOFT LINK
    bool success = false;
    char* cp_link = (char *)malloc(strlen(linkpath) + 1);
    strlcpy(cp_link, linkpath, strlen(linkpath) + 1);

    /* cp_name의경로분석*/
    char* file_link = (char *)malloc(strlen(cp_link) + 1);
    struct dir* dir = parse_path(cp_link, file_link);

    cluster_t inode_cluster = fat_create_chain(0);

    //! link file 전용 inode 생성 및 directory에 추가
    success = (dir != NULL
               && link_inode_create(inode_cluster, target)
               && dir_add(dir, file_link, inode_cluster));

    if (!success && inode_cluster != 0)
        fat_remove_chain(inode_cluster, 0);
    
    dir_close(dir);
    free(cp_link);
    free(file_link);

    return success - 1;


    //! HARD LINK
    // char* cp_link = (char *)malloc(strlen(linkpath) + 1);
    // strlcpy(cp_link, linkpath, strlen(linkpath) + 1);
    // char* target_link = (char *)malloc(strlen(linkpath) + 1);
    // strlcpy(target_link, linkpath, strlen(linkpath) + 1);

    // char* cp_file_link = (char *)malloc(strlen(linkpath) + 1);
    // char* target_file_link = (char *)malloc(strlen(linkpath) + 1);

    // struct dir* cur_dir = parse_path(cp_link, cp_file_link);
    // struct dir* target_dir = parse_path(target_link, target_file_link);

    // // printf("현재 스레드의 섹터 넘버 :: %d\n",inode_get_inumber(dir_get_inode(cur_dir)));
    // // printf("타겟 스레드의 섹터 넘버 :: %d\n",inode_get_inumber(dir_get_inode(target_dir)));

    // bool success = dir_add (cur_dir, linkpath, inode_get_inumber(dir_get_inode(target_dir)));

    // dir_close(cur_dir);
    // dir_close(target_dir);

    // free(cp_link);
    // free(target_link);
    // free(cp_file_link);
    // free(target_file_link);

    // return success - 1;

    // printf("만들 파일 :: %s\n", linkpath);
}

// TODO END =============================== for Project 4 ==========================================