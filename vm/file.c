/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

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
	
	ASSERT (length % PGSIZE == 0);
	ASSERT (pg_ofs (addr) == 0);
	ASSERT (offset % PGSIZE == 0);
	// ASSERT (spt_find_page(&thread_current()->spt, addr));
    struct file *mfile = file_reopen(file);

    // printf("여기서 터지나요??\n");
    // printf("addr :: %p\n", addr);
    // printf("mfile 주소 :: %p\n", mfile);

	size_t zero_length = PGSIZE - length;

	while (length > 0 || zero_length > 0) {

        if(vm_alloc_page(VM_FILE, pg_round_down(addr), writable))
            vm_claim_page(addr);

		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		file_seek (mfile, offset);
        // printf("offset :; %d\n", offset);
        // printf("file pos :: %d\n", mfile->pos);
		if (file_read (mfile, addr, page_read_bytes) != (int) page_read_bytes) {
			// file_close(mfile);
            return addr;
			
			// exit(-1);
		}
		memset (addr + page_read_bytes, 0, page_zero_bytes);
		// printf("lazy load file file pos :: %d\n", file->pos);

        length      -= page_read_bytes;
        zero_length -= page_zero_bytes;
        addr 		+= PGSIZE;
        offset 		+= page_read_bytes;
	}
	return addr;
	
}

/* Do the munmap */
void
do_munmap (void *addr) {

    // struct page* page = spt_find_page(&thread_current()->spt, addr);
    // destroy(page);
}
