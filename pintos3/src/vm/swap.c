#include "vm/swap.h"

#include <bitmap.h>
#include "threads/synch.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include <stdio.h>

/* Bitmap of free swap slots */
struct bitmap *swap_bitmap;

/* Swap partition */
struct lock swap_lock;
struct block *swap_block;

/* Initialize values relative to swap */
void 
swap_init (size_t size)
{
	/* Get swap block */
	swap_block = block_get_role (BLOCK_SWAP);

	/* Create bitmap */
	swap_bitmap = bitmap_create (size);

	/* Initialize bitmap to 0 */
	bitmap_set_all (swap_bitmap, 0);

	/* Initialize swap lock */
	lock_init(&swap_lock);
}

/* From Swap block to Memory */
void
swap_in (size_t used_index, void *kaddr)
{
	unsigned i;
	lock_acquire (&swap_lock);

	/* PGSIZE / BLOCK_SECTOR_SIZE = 8 */
	/* Read swap memory by block size */
	for(i=0; i<8; i++){
		block_read (swap_block, used_index*8 + i, kaddr + BLOCK_SECTOR_SIZE * i);
	}
	
	/* Notice that swap_slot is used */
	bitmap_set (swap_bitmap, used_index, false);

	lock_release (&swap_lock);
}

/* From Memory to Swap block */
size_t swap_out (void *kaddr)
{
	unsigned i;
	lock_acquire (&swap_lock);

	/* PGSIZE / BLOCK_SECTOR_SIZE = 8 */
	/* Find first free slot on the swap */
	unsigned free_swap_slot = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);

	for(i=0; i<8; i++){
		block_write (swap_block, free_swap_slot*8 + i, kaddr + BLOCK_SECTOR_SIZE * i);
	}

	lock_release (&swap_lock);
	return free_swap_slot;	
}

