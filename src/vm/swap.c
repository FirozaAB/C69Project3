#ifdef VM
#warning "Compiling vm module: swap.c"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* 4 KB page, 512 bytes block sectors.
 */
#define SECTORS_PER_PAGE 8


static struct block *swap_block;     
static struct bitmap *swap_bitmap;   
static struct lock swap_lock;        
void swap_init(void)
{
    lock_init(&swap_lock);
    swap_block = block_get_role(BLOCK_SWAP);
    if (!swap_block) {
        PANIC("swap not available\n");
        return; 
    }
  
    // calculate # of slots
    size_t swap_size = block_size(swap_block); 
    size_t slot_count = swap_size / SECTORS_PER_PAGE; 
    swap_bitmap = bitmap_create(slot_count);
    if (!swap_bitmap){
      PANIC("failed to create swap bitmap\n");
    }
    bitmap_set_all(swap_bitmap, false);  
}

/* Write frame to an empty slot in swap.
   Returns swapindex. */
size_t swap_out(void *frame)
{
    lock_acquire(&swap_lock);
    // Find next free slot in swap space
    size_t swap_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    if (swap_index == BITMAP_ERROR){
        lock_release(&swap_lock);
        PANIC("no free slots in swap space (bitmap reported)\n");
    }

    // write frame to swap sector-by-sector
    size_t sector_base = swap_index * SECTORS_PER_PAGE;
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
        block_write(swap_block, sector_base + i,
                  (uint8_t *)frame + i * BLOCK_SECTOR_SIZE);
    }

    lock_release(&swap_lock);
    return swap_index;
}

/* Write from swap space into frame */
void swap_in(size_t swap_index, void *frame){
    lock_acquire(&swap_lock);
    if (!bitmap_test(swap_bitmap, swap_index))
    {
      lock_release(&swap_lock);
      PANIC("invalid swap slot\n");
    }
    // read 8 512-byte sectors into frame (4KB)
    size_t sector_base = swap_index * SECTORS_PER_PAGE;
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
        {
        block_read(swap_block, sector_base + i,
                    (uint8_t *)frame + i * BLOCK_SECTOR_SIZE);
        }

    // update bitmap
    bitmap_flip(swap_bitmap, swap_index);
    lock_release(&swap_lock);
}

/* Mark slot @ swap_index as free */
void swap_free(size_t swap_index)
{
    lock_acquire(&swap_lock);
    if (!bitmap_test(swap_bitmap, swap_index)) // check if already free'd
    {
      lock_release(&swap_lock);
      return;
    }

    bitmap_flip(swap_bitmap, swap_index);  // update bitmap
    lock_release(&swap_lock);
}
#endif