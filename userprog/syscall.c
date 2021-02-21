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

/* ADD header for page fault */
// #include "userprog/exception.h"
// #include "userprog/process.h"
// #include "threads/init.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* 헤더에 넣으면 오류가 나요 */
void* check_address(void *addr);
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

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
    
    lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

    /* rsp 유효성 검증 */
    /* 우리는 상한선에서 출발해서 밑으로 쌓았다. */
    //! ADD: check_address 주석
    check_address(f->rsp);

    uint64_t number = f->R.rax;
    switch(number){
        case SYS_HALT :
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK :
            memcpy(&thread_current()->fork_tf, f,sizeof(struct intr_frame));
            f->R.rax = fork(f->R.rdi);
            break;
        case SYS_EXEC :
            //! ADD: insert check_valid_string
            // check_valid_string(f->R.rdi, f->rsp);
            f->R.rax = exec(f->R.rdi);
            break;
        case SYS_WAIT:  
            f->R.rax = wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi) ;
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi) ;
            break;
        case SYS_OPEN :
            //! ADD: insert check_valid_string
            // check_valid_string(f->R.rdi, f->rsp);
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            //! ADD: insert check_valid_buffer instead of check_address
            // check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            // check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
            //! ADD:가 아니라 check_valid_string 만들지 않음(PPT랑 다름)
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK :
            seek(f->R.rdi,f->R.rsi);
            break;
        case SYS_TELL:
            tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;
    }
	// thread_exit ();
}

/*** It could be dangerous ***/
//! ADD: check_address
void* check_address(void *addr){
    if (is_kernel_vaddr(addr))
    {
        exit(-1);
    }
    // return spt_find_page(&thread_current()->spt, addr);
}
//! END: check_address

// //! ADD: check_valid_buffer
// void check_valid_buffer(void* buffer, unsigned size, void* rsp, bool to_write)
// {
//     /* 인자로받은buffer부터buffer + size까지의크기가한페이지의크기를넘을수도있음*/
//     /*check_address를이용해서주소의유저영역여부를검사함과동시에vm_entry구조체를얻음*/
//     /* 해당주소에대한vm_entry존재여부와vm_entry의writable멤버가true인지검사*/
//     /* 위내용을buffer부터buffer + size까지의주소에포함되는vm_entry들에대해적용*/
//     for(int i = 0; i <= size; i++)
//     {
//         struct page* page = check_address((char *)buffer + i);
//         if(page != NULL)
//         {
//             if(to_write == true)
//             {
//                 if(page->writable == false)
//                 {
//                     exit(-1);
//                 }

//             }
//         }
//     }
// }
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


void halt(void){
    power_off();
}
void exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;
    curr->is_exit = 1; // be dead by exit syscall!
    // hex_dump(USER_STACK-PGSIZE, (void *)(USER_STACK-PGSIZE), PGSIZE, 1);
    // printf("여기 들어옴??\n");
    printf("%s: exit(%d)\n", thread_current()->name, thread_current()->exit_status);
    thread_exit();
}

pid_t fork(const char *thread_name){
    // printf("I'm %d, syscall-fork\n", thread_current()->tid);
    // printf("I'm %d, syscall-fork - fd_table[2] : %p\n", thread_current()->tid, thread_current()->fd_table[2]);
    // printf("I'm %d, syscall-fork - fd_table[3] : %p\n", thread_current()->tid, thread_current()->fd_table[3]);

    return process_fork(thread_name,&thread_current()->fork_tf);
}

int exec(const char *file){
    if(process_exec(file))
        return -1;
}

int wait(pid_t pid){
    return process_wait(pid);
}
bool create(const char *file, unsigned initial_size){
    if (file)
        return filesys_create(file,initial_size); // ASSERT, dir_add (name!=NULL)
    else
        exit(-1);
}
bool remove(const char *file){
    if (file)
        return filesys_remove(file);
    else
        exit(-1);
}
int open(const char *file){
    // printf("I'm %d, syscall_open %s\n", thread_current()->tid,file);

    /*thanks filesys_open : NULL, if there isn't */
    if (file)
    {
        struct file * open_file = filesys_open(file);
        if (open_file)
        {
            return process_add_file(open_file);
        }
        else
            return -1;
    }
    else
        return -1;

}
int filesize(int fd){
    struct file *want_length_file = process_get_file(fd);
    int ret =-1;
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
int read(int fd, void *buffer, unsigned length){
    lock_acquire(&filesys_lock);
    struct file *target = process_get_file(fd);
    int ret = -1;
    if(target) /* fd == 0 이 었으면, 0을 return 했을 것이다.*/
    {   
        if (fd == 0)
        {   
            ret = input_getc();
        }
        else
        {
            ret = file_read(target,buffer,length);
        }
    }
    lock_release(&filesys_lock);
    return ret;
}
int write(int fd, const void *buffer, unsigned length){
    lock_acquire(&filesys_lock);
    struct file *target = process_get_file(fd);
    int ret = -1;
    if(target)
    {   
        if (fd == 1)
        {
            putbuf(buffer, length);
            ret = sizeof(buffer);
        }
        else
        {
            /* 실제로는 inode의 writable이 더 중요하다 !!! */
            ret = file_write(target,buffer,(off_t) length);
        }
    }
    lock_release(&filesys_lock);
    return ret;
}
void seek(int fd, unsigned position){
    struct file *target = process_get_file(fd);
    file_seek(target, position);
}
unsigned tell(int fd){
    struct file *target = process_get_file(fd);
    return file_tell(target);
}
void close(int fd){
    process_close_file(fd);
}
