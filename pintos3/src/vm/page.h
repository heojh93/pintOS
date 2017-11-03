#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <debug.h>
#include <list.h>
#include <hash.h>
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

struct vm_entry{
	uint8_t type;			/* VM_BIN VM_FILE VM_ANON */
	void *vaddr;			/* Page number of vm_entry */
	bool writable;			/* Write correspond address */
	
	bool is_loaded;			/* Is file loaded to physical memory or not */
	struct file* file;		/* File that has mapping with virtual address */

	/* memory mapped file */
	struct list_elem mmap_elem; /* mmap list element */

	size_t offset;			/* offset to be read */
	size_t read_bytes;		/* Size of written data to the virtual page */
	size_t zero_bytes;		/* Remain bytes of page to be filled with zero */
	
	/* swapping */
	size_t swap_slot;		/* Swap slot */

	struct hash_elem elem;	/* Hash Table element */
};

void vm_init (struct hash *vm);
void vm_destroy (struct hash *vm);

struct vm_entry *find_vme (void *vaddr);
bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);

bool load_file (void *kaddr, struct vm_entry *vme);
bool handle_mm_fault (struct vm_entry *vme);

#endif
