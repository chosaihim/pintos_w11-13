/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

//! ADD : initializer를 위해
#include "vm/anon.h"
#include "vm/file.h"
#include "userprog/process.h"
//! END

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */

    //! ADD: initialize Hash table
    hash_init(&thread_current()->spt.pages, page_hash, page_less, NULL);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
    int ty = VM_TYPE(page->operations->type);
    switch (ty)
    {
    case VM_UNINIT:
        return VM_TYPE(page->uninit.type);
    default:
        return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux)
{
    // printf("============= VM_TYPE :: %d =============\n", type);
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    // printf("upage addr :: %p\n", upage);
    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL)
    {
        // printf("PPPPPPPPPPPPPPPPP\n");
        /* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
        //! ADD: uninit_new
        struct page* page = (struct page*)malloc(sizeof(struct page));
        // struct page *page;
        //  = palloc_get_page(PAL_USER | PAL_ZERO);
        // if (upage == NULL)
        //     goto err;

        typedef bool (*initializerFunc)(struct page *, enum vm_type, void *);
        initializerFunc initializer = NULL;

        switch(type){
            case VM_ANON:
                initializer = anon_initializer;
                break;
            case VM_FILE:
                initializer = file_backed_initializer;
                break;
        }
        
        // printf("PPPPPPPPPPP22222222222222\n");
        // bool succ = uninit_initialize(upage, NULL);
        uninit_new(page, upage, init, type, aux, initializer);

        /* TODO: Insert the page into the spt. */
        return spt_insert_page(spt, page);
        //! END: uninit_new
    }
    // printf("AFTER if PPPPPPPPPPP22222222222222\n");
err:
    // printf("FALSESEP22222222222222\n");
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
    struct page* page;
    /* TODO: Fill this function. */
    //! ADD : find_vme
    struct hash_elem *e;

    // printf("BEFORE hash find \n");
    // printf("va :: %d\n", (uint64_t)PGMASK);
    page->va = pg_round_down(va);
    // printf("page.va :: %p\n", page.va);
    // printf("AFTER pg_round_down \n");
    // printf("spt->pages :: %p\n", &spt->pages);
    // printf("page->hash_elem :: %p\n", &page.hash_elem);
    e = hash_find(&spt->pages, &page->hash_elem);
    // printf("e :: %p", e);
    // printf("AFTER hash find \n");
    // free(page);
    return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
    //! END : find_vme;;;;;;;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED)
{
    int succ = false;
    /* TODO: Fill this function. */
    //! ADD: vm_insert
    struct hash_elem *e = hash_insert(&spt->pages, &page->hash_elem);
    if (e == NULL)
    {
        succ = true;
    }
    //! END: vm_insert
    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
    struct frame *frame = palloc_get_page(PAL_ZERO | PAL_USER);
    /* TODO: Fill this function. */
    //! ADD: vm_get_frame
    frame->kva = palloc_get_page(PAL_ZERO | PAL_USER);
    if(frame == NULL | frame->kva == NULL)
    {
        PANIC("todo\n");
    }
    // printf("vm_get_page!! \n");

    frame->page = NULL;
    //! END: vm_get_frame

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    // printf("addr :: %p\n", addr);
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    //! ADD: modify vm_try_handle_fault

    page = spt_find_page(spt, addr);
    // printf("page 주소 :: %p\n", page);
    if (page == NULL) return false;
    // printf("page addr :: %p\n", addr);
    if (not_present){

        // printf("ee\n");
        return vm_do_claim_page(page);
    }
    else
        return false;

}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
    struct page *page = NULL;
    /* TODO: Fill this function */
    //! ADD: vm_claim_page
    page = spt_find_page(&thread_current()->spt, va);
    //! END: vm_claim_page
    // printf("여기서 터지나요??\n");

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
    // printf("page addr in vm_do :: %p\n", page);
    struct frame *frame = vm_get_frame();
    // printf("frame addr :: %p\n", frame);
    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    // struct thread *curr = thread_current();
    //! ADD: insert pml4_set_page
    // TODO : mapping va to pa in the page table
    // printf("frame :: %p\n", frame);
    // printf("page :: %p\n", page);
    // printf("page->frame :: %p\n", page->frame);
    // printf("frame->page :: %p\n", frame->page);
    // printf("page->va :: %p\n", page->va);
    // printf("frame->kva :: %p\n", frame->kva);
    if(install_page(page->va, frame->kva, page->writable))
    {
        // printf("여기서 터지나요??\n");
        return swap_in(page, frame->kva);
    }
    return false;
    
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
    //! ADD: spt init
    // printf("supple &thread_current()->spt.pages :: %p\n", &thread_current()->spt.pages);
    // printf("supple page init !! \n");
    hash_init(&spt->pages, page_hash, page_less, NULL);
    // printf("supple page init 222!! \n");
    //! END: spt init
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED)
{
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
    //! ADD: hash_destroy = vm_destroy
    hash_clear (&spt->pages, spt_destructor);
}

//! ADD: Functions for hash table
//! ADD: page_hash = vm_hash_func
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
//! ADD: page_less = vm_less_func
bool page_less(const struct hash_elem *a_,
               const struct hash_elem *b_, void *aux UNUSED)
{
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}

bool insert_page(struct hash *pages, struct page *p)
{
    if (!hash_insert(pages, &p->hash_elem))
        return true;
    else
        return false;
}
bool delete_page(struct hash *pages, struct page *p)
{
    if (!hash_delete(pages, &p->hash_elem))
        return true;
    else
        return false;
}

//! ADD: destructor
void spt_destructor(struct hash_elem *e, void* aux)
{
    const struct page *p = hash_entry(e, struct page, hash_elem);
    vm_dealloc_page(p);
}
