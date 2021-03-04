#ifndef FILESYS_PAGE_CACHE_H
#define FILESYS_PAGE_CACHE_H
#include "vm/vm.h"
#include "threads/synch.h"

struct page;
enum vm_type;

//! struct buffer_head
struct page_cache {
    //! ADD
    bool is_dirty;
    bool in_use;
    void* disk_sector;
    bool clock_bit;
    struct lock page_cache_lock;
    void* page_cache_entry;
};

void page_cache_init (void);
bool page_cache_initializer (struct page *page, enum vm_type type, void *kva);
#endif
