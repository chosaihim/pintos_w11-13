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

/* ADD header for page fault */
// #include "userprog/exception.h"
// #include "userprog/process.h"
// #include "threads/init.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* 헤더에 넣으면 오류가 나요 */
void check_address(void *addr);
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
    check_address(f->rsp);

    /*rsp 부터 인자들을 arg에 저장하기 */
    // get_frame_argument(f,arg);
    // get_argument()

    uint64_t number = f->R.rax;
    switch(number){

    case SYS_HALT :

        halt();
        break;

    case SYS_EXIT:

        // int status = f->R.rdi;
        exit(f->R.rdi);
        break;
    case SYS_FORK :
        // process_create_initd(thread_name);
        // char* thread_name = f->R.rdi;

        memcpy(&thread_current()->fork_tf, f,sizeof(struct intr_frame));
        f->R.rax = fork(f->R.rdi);
        break;
    case SYS_EXEC :
        // exec(file);
        // char * file = f->R.rdi;
        // printf("I'm EXEC ! \n");
        f->R.rax = exec(f->R.rdi);
        break;
    case SYS_WAIT:  
        // wait(pid);
        // pid_t pid = f->R.rdi;
        f->R.rax = wait(f->R.rdi);
        break;
    case SYS_CREATE:
        // create(file, initial_size);
        // char* file = f->R.rdi;
        // unsigned initial_size = f->R.rsi;
        f->R.rax = create(f->R.rdi, f->R.rsi) ;
        break;
    case SYS_REMOVE:
        // remove(file);
        // char* file = f->R.rdi;
        f->R.rax = remove(f->R.rdi) ;
        break;
    case SYS_OPEN :
        // open(file);
        // char* file = f->R.rdi;
        f->R.rax = open(f->R.rdi);
        break;
    case SYS_FILESIZE:
        // filesize(fd);
        // int fd = f->R.rdi;
        f->R.rax = filesize(f->R.rdi);
        break;
    case SYS_READ:
        // read(fd, buffer, length);
        // int fd = f->R.rdi;
        // void * buffer = f->R.rsi;
        // unsigned length = f->R.rdx;
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_WRITE:
        // write(fd, buffer, length);
        // int fd = f->R.rdi;
        // void *buffer = f->R.rsi;
        // unsigned length = f->R.rdx;
        // printf(">>>>> I'm WRITE ! \n");
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_SEEK :
        // seek(fd, position);
        // int fd = f->R.rdi;
        // unsigned position = f->R.rsi;
        seek(f->R.rdi,f->R.rsi);
        break;
    case SYS_TELL:
        // tell(fd);
        // int fd = f->R.rdi;
        tell(f->R.rdi);
        break;
    case SYS_CLOSE:
        // close(fd);
        // int fd = f->R.rdi;
        close(f->R.rdi);
        break;
    }
	// thread_exit ();
}

/*** It could be dangerous ***/
void check_address(void *addr){
    if (is_kernel_vaddr(addr))
    {
        exit(-1);
    }
}


void halt(void){
    power_off();
}
void exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;
    curr->is_exit = 1; // be dead by exit syscall!
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
            // printf("read : %d\n", ret);
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
