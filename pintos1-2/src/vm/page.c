#include "page.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <string.h>
#include <stdio.h>

static unsigned 
vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *v_etr;
	
	/* hash_entry() : find vm_entry structure about e */
	v_etr = hash_entry(e, struct vm_entry, elem);

	/* hash_int() : return hash value of vaddr of vm_entry */
	return hash_int((int)v_etr->vaddr);

}
	

/* b > a : true , a > b : false */
static bool 
vm_less_func(const struct hash_elem *a, 
		const struct hash_elem *b, void *aux UNUSED)
{
	struct vm_entry *a_etr, *b_etr;
	a_etr = hash_entry(a, struct vm_entry, elem);
	b_etr = hash_entry(b, struct vm_entry, elem);

	return b_etr->vaddr > a_etr->vaddr;
}

void 
vm_init(struct hash *vm)
{
	ASSERT (vm != NULL);
	/* hash_init() : Initialize hash table */
	/* Use vm_hash_func & vm_less_func */
	hash_init(vm, vm_hash_func, vm_less_func, NULL);

}

/* Remove memory of vm_entry */
void 
vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	struct thread *t = thread_current();
	/* If vm_entry loaded */
	if(vme->is_loaded == true){

		/* find page through pagedir_get_page() and free page */
		palloc_free_page(pagedir_get_page(t->pagedir, vme->vaddr));

		/* Free page mapping */
		pagedir_clear_page(t->pagedir, vme->vaddr);
	}
	free(vme);
}

/* Insert vm_entry into Hash Table */
bool 
insert_vme(struct hash *vm, struct vm_entry *vme)
{
	struct hash_elem *e = &vme->elem;

	ASSERT (vm != NULL);
	ASSERT (vme != NULL);

	if(hash_insert(vm,e) == NULL) return true;
	else return false;
}

/* Delete vm_entry from Hash Table */
bool 
delete_vme(struct hash *vm, struct vm_entry *vme)
{
	struct hash_elem *e = &vme->elem;

	ASSERT (vm != NULL);
	ASSERT (vme != NULL);
	if(hash_delete(vm,e) == e) return true;
	else return false;
}

/* Find vm_entry which is relevant to vaddr */
struct 
vm_entry *find_vme(void *vaddr)
{
	struct vm_entry vme;
	struct hash_elem *e;
	
	vme.vaddr = pg_round_down(vaddr);
	e = hash_find(&thread_current()->vm, &vme.elem);

	if(e == NULL){
		return NULL; 
	}
	else {
		return hash_entry(e, struct vm_entry, elem);
	}
}

/* Destroy bucket of Hash Table & vm_entry */
void 
vm_destroy(struct hash *vm)
{
	ASSERT (vm != NULL);
	hash_destroy(vm, vm_destroy_func);
}

/* Load real file of disk to physical page */
bool 
load_file (void *kaddr, struct vm_entry *vme)
{
	/* write data to physical page using file_read_at() */
	if(file_read_at(vme->file,kaddr,vme->read_bytes,vme->offset)
			!= (off_t)(vme->read_bytes)){
		return false;
	}
	/* Fill '0' in remain area (zero bytes)*/
	memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
	return true;
}
