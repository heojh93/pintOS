#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include <stdio.h>


static struct list_elem *get_next_lru_clock(void);


/* Initialize lru */
void
lru_list_init(void)
{
	list_init(&lru_list);
	lock_init(&lru_list_lock);
	lru_clock = NULL;
}

/* Add page to lru list */
void
add_page_to_lru_list (struct page *page)
{
//	lock_acquire (&lru_list_lock);
	list_push_back (&lru_list, &page->lru);
//	lock_release (&lru_list_lock);
}

/* Delete page from lru list */
void
del_page_from_lru_list (struct page *page)
{
//	if(lru_clock == &page->lru)
//		lru_clock = list_remove(&page->lru);
//	else
		list_remove(&page->lru);
}

/* Next node of lru_clock */
static struct list_elem *
get_next_lru_clock (void)
{
	struct list_elem *n = list_next(lru_clock);
	/* Begin lru clock or Re-begin lru clock */
	if(n == list_end(&lru_list)){
		if(list_size(&lru_list)==1) return NULL;
		n = list_begin(&lru_list);
	}

	return n;
}

/* Evict victim page and secure memory using clock-algorithm */
void*
try_to_free_pages (enum palloc_flags flags UNUSED)
{
	
	if(!lru_clock){
		lru_clock = list_begin(&lru_list);
	}
	while(lru_clock){
		struct list_elem *n = get_next_lru_clock();
		struct page *p = list_entry (lru_clock, struct page, lru);
		struct vm_entry *pe = p->vme;
		
		lru_clock = n;

		/* 1. Accessed bit = 1 */
		if(pagedir_is_accessed(p->thread->pagedir, pe->vaddr)){
			pagedir_set_accessed(p->thread->pagedir, pe->vaddr, false);
		}
		/* 2. Accessed bit = 0 */
		else{
			switch(pe->type){
				case VM_BIN:
					if(pagedir_is_dirty(p->thread->pagedir,pe->vaddr)){
						pe->type = VM_ANON;
						pe->swap_slot = swap_out(p->kaddr);
					}
					break;
				case VM_FILE:
					if(pagedir_is_dirty(p->thread->pagedir,pe->vaddr)){
						lock_acquire (&filesys_lock);
						file_write_at (pe->file, pe->vaddr, pe->read_bytes, pe->offset);
						lock_release (&filesys_lock);
					}
					break;
				case VM_ANON:
					pe->swap_slot = swap_out(p->kaddr);
					break;
			}
			pe->is_loaded = false;
			pagedir_clear_page (p->thread->pagedir, p->vme->vaddr);
			__free_page(p);
			return palloc_get_page(flags);
		}
	}
	return NULL;

}
