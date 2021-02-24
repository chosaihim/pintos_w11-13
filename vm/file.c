/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	
    struct file *mfile = file_reopen(file);

	void *return_addr = addr;

    // printf("여기서 터지나요??\n");
    // printf("addr :: %p\n", addr);
    // printf("mfile 주소 :: %p\n", mfile);
    // printf("file 주소 :: %p\n", file);

	// length = length > file_length(file) ? file_length(file) : length;
	size_t zero_length = PGSIZE - (length % PGSIZE);

	while (length > 0 || zero_length > 0) {

		// spt_find_page(&thread_current()->spt, addr);

		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct box *box = (struct box *)malloc(sizeof(struct box));

		box->file = mfile;
		box->ofs = offset;
		box->page_read_bytes = page_read_bytes;

		// file_seek (mfile, offset);
        // printf("offset :; %d\n", offset);
        // printf("file pos :: %d\n", mfile->pos);
        if(!vm_alloc_page_with_initializer(VM_FILE, pg_round_down(addr), writable, lazy_load_segment, box))
			return NULL;
		// memset (addr + page_read_bytes, 0, page_zero_bytes);
		// printf("lazy load file file pos :: %d\n", file->pos);
		// printf("is dirty mmap :: %d\n", pml4_is_dirty (&thread_current()->pml4, page->va));
		// pml4_set_dirty(&thread_current()->pml4, page->va, 0);
		// printf("is dirty mmap :: %d\n", pml4_is_dirty (&thread_current()->pml4, page->va));
		// printf("is dirty after mmap :: %d\n", pml4_is_dirty (&thread_current()->pml4, addr));
		// printf("file dirty :: %d\n", pml4_is_dirty(&thread_current()->spt, addr));
		// printf("addr :: %p\n", return_addr);
		// hex_dump(page->va, page->va, PGSIZE, true);

        length      -= page_read_bytes;
        zero_length -= page_zero_bytes;
        addr 		+= PGSIZE;
        offset 		+= page_read_bytes;
	}
	return return_addr;
	
}

/* Do the munmap */
void
do_munmap (void *addr) {

	// printf("addr 주소 111 :: %p\n", addr);
	// printf("addr 주소 222 :: %p\n", pg_round_down(addr));
	// printf("addr 주소 111 :: %p\n", addr);
	// printf("여기서 시작 !!! \n");

    while (true)
    {
		// printf("2번째 !!! \n");
		struct page* page = spt_find_page(&thread_current()->spt, addr);
		// printf("page 주소 111 :: %p\n", page);
		if (page == NULL){
			// printf("out\n");
			break;

		}

		// printf("=========== here 111 ============\n");
		struct box* box = (struct box*)page->uninit.aux;
		// printf("read_bytes :; %d\n", box->page_read_bytes);
		// printf("read_bytes :; %d\n", box->ofs);
		// printf("is dirty munmap :: %d\n", pml4_is_dirty (thread_current()->pml4, page->va));
		// printf("스레드 이름 :: %s, page 주소 :: %p\n", thread_name(), page);
		// printf("file 주소 :: %p\n", box->file);
		if(pml4_is_dirty (thread_current()->pml4, page->va))
		{
			file_write_at(box->file, addr, box->page_read_bytes, box->ofs);
			
		}
		// memset (&box->file + box->page_read_bytes, 0, PGSIZE - box->page_read_bytes);

		// hash_delete(&thread_current()->spt.pages, &page->hash_elem);
		// printf("=========== here 222 ============\n");
        // vm_dealloc_page(page);
        // destroy(page);
		// free(box);
		addr += PGSIZE;
    }
}
