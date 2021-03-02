#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	char *program_name, *save_ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
    /**** PARSE command-line and GET program-name, which is first token ****/
    /* using strtok_r */
	program_name = strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (program_name, PRI_DEFAULT, initd, fn_copy); // initd -> process_exec -> parsing 진행됨!!
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

    
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	// printf("hello\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED)
{
	/* Clone current thread to new thread.*/
	tid_t fork_tid = thread_create(name, PRI_DEFAULT, __do_fork, thread_current());

	// printf("I'm %d, process_fork1 - before sema_down(fork)\n", thread_current()->tid);
	// printf("I'm %d, process_fork - fd_table[2] : %p\n", thread_current()->tid, thread_current()->fd_table[2]);

    // intr_dump(if_);
    if (fork_tid > 0) /* 실패하면 -1 임!!!*/
    { 
		sema_down(&thread_current()->sema_fork);
        // if(get_child_process(fork_tid)->pml4 == NULL)
        if(thread_current()->is_fork == 0)
            fork_tid = -1;
    }
	// printf("I'm %d, process_fork2 - after sema_down(fork)\n", thread_current()->tid);
	// printf("I'm %d, process_fork - fd_table[2] : %p\n", thread_current()->tid, thread_current()->fd_table[2]);
    // printf("I'm %d, fork_tid : %d ,process_fork \n", thread_current()->tid, fork_tid);

	return fork_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *)aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if(is_kernel_vaddr(va))
		return true;
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page(parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER);
    if(newpage == NULL)
        return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	  *    TODO: check whether parent's page is writable or not (set WRITABLE
	  *    TODO: according to the result). */
	 memcpy(newpage,parent_page,PGSIZE);
	 writable = is_writable(pte);
	 /* 5. Add new page to child's page table at address VA with WRITABLE
	   *    permission. */
	 if (!pml4_set_page(current->pml4, va, newpage, writable))
	 {
		 /* 6. TODO: if fail to insert page, do error handling. */
         palloc_free_page(newpage);
		 return false;

	}
    // palloc_free_page(newpage);

    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork(void *aux)
{
	struct intr_frame if_;
	struct thread *parent = (struct thread *)aux;
	struct thread *current = thread_current();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent->fork_tf;
	// intr_dump(parent_if);
	// printf("PARENT : I'm %d, __do_fork - fd_table[2] : %p\n", parent->tid, parent->fd_table[2]);

	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy(&if_, parent_if, sizeof(struct intr_frame));
	// intr_dump(&if_);

	// printf("PARENT : I'm %d, __do_fork - fd_table[2] : %p\n", parent->tid, parent->fd_table[2]);
	/* 2. Duplicate PT */
	current->pml4 = pml4_create();

    if (current->pml4 == NULL)
		goto error;

	process_activate(current);
	// printf("PARENT : I'm %d, __do_fork - fd_table[2] : %p\n", parent->tid, parent->fd_table[2]);

#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif
	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	// printf("PARENT : I'm %d, __do_fork - fd_table[2] : %p\n", parent->tid, parent->fd_table[2]);

	for (int fd = parent->next_fd - 1; fd > 1; fd--)
	{
		// printf("fd :: %d\n",fd);
		// printf("I'm %d, do__fork_ - duplicating begin \n", thread_current()->tid);
		// printf("parent ID : %d\n",parent->tid);
		// printf("I'm parent's file, %p\n",parent->fd_table[fd]);
		if (parent->fd_table[fd])
			current->fd_table[fd] = file_duplicate(parent->fd_table[fd]);
		// printf("I'm child's file, %p\n", current->fd_table[fd]);
		// printf("I'm %d, do__fork_ - duplicating end  \n", thread_current()->tid);
	}
	current->next_fd = parent->next_fd;   /* WE NEED THIS !!! */
	// printf("I'm %d, do__fork_2\n", thread_current()->tid);


    parent-> is_fork = 1; /* fork success ! */
	sema_up(&parent->sema_fork); /* 중간에 터지면 깨어주질 못한다. */
	// printf("I'm %d, do__fork_3\n", thread_current()->tid);

	process_init();

	/* Finally, switch to the newly created process. */
	if (succ)
	{
		if_.R.rax = 0;
        // printf("I'm %d, do_iret \n",thread_tid());
		do_iret(&if_);
	}

error:
    parent->is_fork = 0;
    // printf("I'm %d, do__fork_error\n", thread_current()->tid);
	sema_up(&parent->sema_fork); /* 중간에 터지면 깨어주질 못한다. */
	thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */

//! ADD: same as start_process in ppt
int
process_exec (void *f_name) {
	char *file_name = f_name;
	/* not referencing , TEST for exec() */
	char file_static_name[64];
	memcpy(file_static_name,file_name,strlen(file_name)+1);

	char *token, *save_ptr;
    char *argv[64]; // size will be changed
	int argc = 0;
    // int idx = 0;
	bool success;
    /**** TOKENIZE arguments & COUNT the number of tokens ****/
    /* strtok_r()을 이용한다! */
    for (token = strtok_r(file_static_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
    {
        // 배열에 문자열 삽입 -- 결국 token은 주소다.
		argv[argc] = token;
        argc++;
    }

    /* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();
	
	#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
	#endif

	/* And then load the binary, including set up stack! */
	thread_current()->is_load = success = load (argv[0], &_if);

	/* 실패시, argument stack 도 못하게 만들자 !!!*/
	/* If load failed, quit. */
	if (!success)
	{
		/* pdf를 어겼습니다. */
		// thread_current()->is_load=0;
		return -1;
	}

	/* store argument before exec user programs */
	argument_stack(argv, argc, &_if);
	// hex_dump(_if.rsp, _if.rsp, USER_STACK-_if.rsp, true);
	// printf("if->rdi %d\n", (int)_if->rdi);

	/* exec으로 넘어온 인자는 kernel_vaddr이 아니다!! -- register 값 바로 빼오고있음 */
	if(is_kernel_vaddr(file_name))
		palloc_free_page (file_name); /* 결국 file_name 은 palloc get page 됐던, fn_copy였다. */

	/* load success ?!*/
	// thread_current()->is_load = 1;
	/* Start switched process. */
	do_iret(&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *wait_thread = get_child_process(child_tid);

    int return_status ;
	if (wait_thread == NULL) return -1;
	sema_down(&wait_thread->sema_exit); // 커널이 죽여도 sema 풀어주나? : YES

	if(wait_thread->is_exit)
		 return_status = wait_thread->exit_status;
	else
    {
		return_status = -1;
    }

	remove_child_process(wait_thread);


	return return_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	/* 커널이 죽으면(==halt()) 출력하지말라!! */
	// #if USERPROG
	// 	printf("%s: exit(%d)\n", curr->name, curr->exit_status);
	// #endif

	/* close the all running file */
	for(int fd = curr->next_fd-1; fd>=2; fd --)
	{
		process_close_file(fd);
	}

    /* 가장 먼저 실행되는 파일은 open 시킨 파일이 아니다. 바로 load 된 것이다.  */
    if(curr->running_file)
    	file_close(curr->running_file); 
		/* 얘 왜 추가해주지?????? 추가하니까 왜 되지???? (위에 답변) */
		/* load 시에도 file_open 해주었다. -- file_close 필요하다. */

    palloc_free_page(curr->fd_table);

    //! ADD: vm_destroy
    // supplemental_page_table_kill(&curr->spt);

    free_children();
	/* 순서 주의 */
	process_cleanup (); /* pml4 를 끝낸다. */
	sema_up(&curr->sema_exit);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	if(!hash_empty(&curr->spt.pages))
		supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* Store the variables on user stack */
/* parse : memory space that store program's name & arguments */
/* count : the number of argument */
/* _if : <*if : intr_frame>  */
void argument_stack(char **argv, int argc, struct intr_frame *if_)
{
	/* rsp : rsp 주소를 담고있는 공간이다!! REAL rsp : *rsp   */
	// rsp : stack pointer -- stack을 구분할 수 있는 지점 (== 스택 시작점)

	/* insert arguments' address */ 
	char* argu_address[128];

	for(int i = argc-1; i >=0; i--)
	{
		int argv_len = strlen(argv[i]);
		/* strlen은 '\0'을 제외한다. */
		if_->rsp = if_->rsp-(argv_len+1);
		/* store adress seperately */
		argu_address[i] = if_->rsp;
		memcpy(if_->rsp, argv[i], argv_len+1);

		//이러면 4바이트가 삽입된다.
		// *(char **)(if_->rsp) = argv[i][j]
	}

	/* insert padding for word-align */
	while(if_->rsp %8 != 0)
	{
		if_->rsp --;
		*(uint8_t *)(if_->rsp) = 0;
	}


	/* insert address of strings including sentinel */
	for (int i = argc; i >= 0; i--)
	{
		if_->rsp = if_->rsp - 8;

		if (i==argc)
			memset(if_->rsp, 0, sizeof(char**));
		else
			memcpy(if_->rsp, &argu_address[i], sizeof(char**));
			// argu_adress[i]값을 복사하려면, argu_address[i]의 주소를 cpy요소로 넣어라!!
	}
	
	/* fake return address */
	if_->rsp = if_->rsp-8;
	memset(if_->rsp,0,sizeof(void*));

	/*
	Check this out.

	if_->rsp = if_->rsp-8;
	memcpy(if_->rsp, &argc, sizeof(int));
	if_->rsp -= 8;
	memcpy(if_->rsp,&argu_address[0],sizeof(char*))
	*/

	/* We need to check again */
	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp+8; /* 이녀석 주의!!! */
}

struct thread *get_child_process(int pid){

	struct thread *curr = thread_current();
	if (!list_empty(&curr->children))
	{

        struct list_elem *horse = list_begin(&(curr->children));
		while (horse != list_end(&(curr->children)))
		{
            struct thread *horse_thread = list_entry(horse, struct thread, children_elem);
            if (horse_thread->tid == pid)
			{
                return horse_thread;
			}
            horse = horse->next;
		}
	}
	return NULL;
}

/* 좀비가 됐던 process들 모두 free, 
    고아가 될 수 있는 process들 모두 initial_thread로 부모 이전
*/
void free_children(void){
    struct thread *curr = thread_current();
    if (!list_empty(&curr->children))
    {

        // struct list_elem *horse = list_pop_front(&(curr->children));
        // struct list_elem *tail = list_end(&curr->children);
        // while(horse != tail)

        struct list_elem *horse = list_begin(&(curr->children));
        while (horse != list_end(&(curr->children)))
        {
            struct thread *horse_thread = list_entry(horse, struct thread, children_elem);
            if (horse_thread->status == THREAD_DYING)
            {
                /* prevent Zombie Process*/
				horse = list_remove(horse);
				palloc_free_page(horse_thread);
            }
            else
            {
				/* 살아있는 thread는 부모가 죽으면 본인이 죽을 때, destruction_req에 들어갈 것이다.
					그래서 고아 프로세스가 메모리 누수를 발생시키지 않을 것이라고 생각한다.
				*/
				horse = horse->next;
            }
        }
    }
}

void remove_child_process(struct thread *cp){
	list_remove(&cp->children_elem);
	palloc_free_page(cp); 
	/* 나는 부모가 종료될 때, 이미 죽었으나, destruction req에 들어가지 못한 녀석들을 free 시켜준다.*/

	/* wait한다는 것은 부모가 종료되지 않은 녀석을 기다린다는 것을 의미하니, 
	free를 이곳에서 시켜도 된다. 
	
	결국 이 함수는 free_children의 subset이다.*/

}

int process_add_file(struct file *f){
	struct thread *curr = thread_current();
	// *(curr->fd_table + curr->next_fd) = f;
	// printf("I'm %d, process_add_file\n", thread_current()->tid);

	// printf("I'm %d, before process_add_file next_fd : %d\n", thread_current()->tid, curr->next_fd);
    if (curr->next_fd > 511)
    {
        file_close(f);
        return -1;
    }
    curr->fd_table[curr->next_fd] = f;
	// printf("I'm %d, after process_add_file curr->fd_table[%d] : %p\n", curr->tid,curr->next_fd,curr->fd_table[curr->next_fd]);

	return curr->next_fd++;
}
struct file *process_get_file(int fd){
	struct thread *curr = thread_current();
	struct file* fd_file = curr->fd_table[fd];
	// struct file* fd_file = *(curr->fd_table + fd);

	/* 설마 fd로 음수를 넘겨주진 않겠지?*/
	
	/* fd_table[0], fd_table[1]도 값이 있다. */
	if(fd_file)
		return fd_file;
	else
		return	NULL;

	/* Ver 0.1 */
	// /* 해당 파일 존재하면, : NULL이 아니면  (memset에서 0으로 초기화) */
	// if(fd >= 2){
	// 	if(fd_file)
	// 		return fd_file;
		
	// 	else
	// 		return NULL;
	// }

	// else{ /* 0과 1도 file이 있는 것으로 인식 시켜주기  for read & write */
	// 	return 1;
	// }
		
}
void process_close_file(int fd){
	// file_close : NULL 처리 확실함
	file_close(process_get_file(fd));
	thread_current() -> fd_table[fd] = NULL;
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

//! static -> 전역으로 변환했음 (께림칙)
bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();       /* pml4 : Page-Map Level 4 Table*/
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	lock_acquire(&filesys_lock);
	/* Open executable file. */
	file = filesys_open (file_name);

	if (file == NULL) {
		lock_release(&filesys_lock);
		printf("load: %s: open failed\n", file_name);
		goto done;
	}
	/* ADD for denying write to excutable */
	lock_release(&filesys_lock);

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}
	t->running_file = file;
	file_deny_write(t->running_file); /* 가장 먼저 load부터 시킨다. (== open 시키지 않는다! ) */
	
	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */

	// file_close (file); /* CHANGE ---- close the file when process exists */
	return success;
}

bool
check_excutable(struct file * file)
{
	bool res = true;
	struct ELF ehdr;

	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
		res = false;
	
	return res;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);
		// hex_dump(kpage, kpage, PGSIZE, true);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */
//! ADD: install_page
// bool install_page (void *upage, void *kpage, bool writable);
//! ADD: VM에서 가지고 가려고, static제거!!!!!
//! static bool //이게 original code
bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}


//! ADD : static 해제
bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
    //! ADD: lazy_load_segment
    //! 이게 맞나?; aux[0]을 *file로 casting하고 싶어서, 참조 가능한 이중 void 포인터로((void **)aux) 먼저 캐스팅
	// TODO : page 구조체 member로 넣어놓은 것들 불러오기

    struct file *file = ((struct box *)aux)->file;
	off_t ofs = ((struct box*)aux)->ofs;
    size_t page_read_bytes = ((struct box *)aux)->page_read_bytes;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */

    /* Load this page. */

	file_seek (file, ofs);

    if (file_read (file, page->frame->kva, page_read_bytes) != (int) page_read_bytes) {
        palloc_free_page (page->frame->kva);
        return false;
    }
	// printf("여기서 터지나요??\n");
    // printf("lazy load file file pos :: %d\n", file->pos);
    memset (page->frame->kva + page_read_bytes, 0, page_zero_bytes);
    // /* Add the page to the process's address space. */

    // printf("here??\n");
    // printf("upage-va :: %p\n", page->va);
    // hex_dump(page->va, page->va, PGSIZE, true);
    // free(aux);
    return true;
    //! END: insert of lazy_load_segment
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		// TODO: Set up aux to pass information to the lazy_load_segment. */
        //! ADD: aux modified

        struct box *box = (struct box*)malloc(sizeof(struct box));

        box->file = file;
        box->ofs = ofs;
        box->page_read_bytes = page_read_bytes;

		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, box))
			return false;
		// free(box);
		// hex_dump(page->va, page->va, PGSIZE, true);
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
        //! ADD : ofs 이동시켜야 함
		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
bool	//! spt copy에서 쓰려고 전역으로 변환
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
    //! ADD: setup_stack
    // printf("========= in setup stack =============\n");
	//! stack 영역인 page임을 MARK
    if (vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, 1))
    {

		success = vm_claim_page(stack_bottom);
		
		if (success){
			// printf("here??\n");
			if_->rsp = USER_STACK;
            thread_current()->stack_bottom = stack_bottom;
		}

    }

    //! END: setup_stack

	return success;
}
#endif /* VM */
