#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdbool.h>
#include "filesys/off_t.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
void argument_stack(char **argv, int argc, struct intr_frame *if_);
struct thread *get_child_process (int pid);
void remove_child_process(struct thread *cp);
int process_add_file (struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
bool check_excutable(struct file *file);
void free_children(void);
//! ADD: VM
bool install_page (void *upage, void *kpage, bool writable);
bool setup_stack (struct intr_frame *if_);
//! ADD: aux 구조체
struct box {
    struct file *file;
    // uint8_t* upage;
    off_t ofs;
    size_t page_read_bytes;
    // bool writable;
};
#endif /* userprog/process.h */
