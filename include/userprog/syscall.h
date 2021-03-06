#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include <debug.h>
#include <stddef.h>
// #include "threads/interrupt.h"
/* Process identifier. */
typedef int pid_t;
typedef int off_t;
void syscall_init (void);

// void check_address(struct intr_frame *f);
// void get_frame_argument(void *rsp, int *arg);

/* Projects 2 and later. */
void halt(void);
void exit(int status);
pid_t fork(const char *thread_name);
int exec(const char *file);
int wait(pid_t);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

//! Project 3 VM
void* mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

// TODO ============================ for Project 4 =================================
bool is_dir(int fd);
bool sys_chdir(const char *path_name);
bool sys_mkdir(const char *dir);
bool sys_readdir(int fd, char *name);
struct cluster_t *sys_inumber(int fd);
int symlink (const char *target, const char *linkpath);

#endif /* userprog/syscall.h */// 