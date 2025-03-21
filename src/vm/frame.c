#ifdef VM
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include <stdio.h>

static struct list ft; /* Frame Table */
static struct lock ft_lock; /* Frame Table Lock */
static struct list_elem *hand; /* Clock Hand */
static bool clock_init = false; /* Clock Hand init flag */

void ft_init(void) {
    list_init(&ft);
    lock_init(&ft_lock);
    hand = NULL;
}

// Allocate a frame for a page, evicting a frame if necessary.
// If pinned is true, the frame will not be evicted.
void *ft_allocate(void *page, bool pinned) {
    // check if kernel or user page
    int page_flag;
    if(!is_user_vaddr(page)){
        page_flag = PAL_ZERO;
    } else {
        page_flag = PAL_USER | PAL_ZERO;
    }
    lock_acquire(&ft_lock); // enter critical section, avoids multiple processes being assigned same frame
    void *frame = palloc_get_page(page_flag);
    while(frame == NULL) { // loop until frame is allocated
        ft_evict();
        frame = palloc_get_page(page_flag);
    }
    // create frame entr
    struct frame_entry *entry = malloc(sizeof(struct frame_entry));
    if (entry == NULL) {
        palloc_free_page(frame);
        lock_release(&ft_lock);
        return NULL;
    }
    entry->frame = frame;
    entry->page = page;
    entry->owner = thread_current();
    if(pinned) {
        entry->pin_status = true;
    } else {
        entry->pin_status = false;
    }
    // Advnce hand
    if (!clock_init) {
        hand = list_begin(&ft);
        clock_init = true;
    }
    list_push_back(&ft, &entry->elem);
    lock_release(&ft_lock); // exit critical section, frame table is safely updated
    return frame;
}

// free frame and remove corresponding frame entry from frame table
void ft_free(void *frame) {
    lock_acquire(&ft_lock);
    struct list_elem *e;
    for (e = list_begin(&ft); e != list_end(&ft); e = list_next(e)) {
        struct frame_entry *entry = list_entry(e, struct frame_entry, elem);
        ASSERT(entry->pin_status == false);
        if (entry->frame == frame) {
            list_remove(e);
            free(entry);
            break;
        }
    }
    lock_release(&ft_lock);
    palloc_free_page(frame);
}

// Implments second chance replacement algorithm, evicts a single victiem frame. 
// If the frame is pinned or is recentley accessesed, it will not be considered.
void ft_evict(void) {
    lock_acquire(&ft_lock);
    while (true) {
        if (hand == NULL) {
            hand = list_begin(&ft);
        }
        if (hand == list_end(&ft)) {
            hand = list_begin(&ft);
            if (hand == list_end(&ft)) { // No frames to evict - should never reach here
                ASSERT(false);
            }
        }
        struct frame_entry *entry = list_entry(hand, struct frame_entry, elem);
        if (entry->pin_status == false) {
            if (pagedir_is_accessed(entry->owner->pagedir, entry->page)) { // give second chance
                pagedir_set_accessed(entry->owner->pagedir, entry->page, false);
            } else { // evict
                // get victim frame
                struct spt_entry *spte = spt_retrieve(&entry->owner->spt, entry->page);
                ASSERT(spte != NULL);
                if (pagedir_is_dirty(entry->owner->pagedir, entry->page)) {
                    if (spte->type == SWAP || spte->type == ZERO) {
                        spte->swap_index = swap_out(entry->frame);
                        spte->type = SWAP;
                    } else { // FILE_BACKED
                        if(spte->file == NULL){
                            spte->swap_index = swap_out(entry->frame);
                            spte->type = SWAP;
                        } else {
                            spte->type = FILE_BACKED;
                            file_write_at(spte->file, entry->frame, spte->read_bytes, spte->offset);
                        }
                    } 
                }
                // free frame, and advnace hand
                pagedir_clear_page(entry->owner->pagedir, entry->page);
                struct list_elem *next = list_next(hand);
                list_remove(hand);
                hand = next;
                palloc_free_page(entry->frame);
                free(entry);
                break;
            }
        }
        hand = list_next(hand);
    }
    lock_release(&ft_lock);
}

void ft_pin(void *frame) {
    lock_acquire(&ft_lock);
    struct list_elem *e;
    for (e = list_begin(&ft); e != list_end(&ft); e = list_next(e)) {
        struct frame_entry *entry = list_entry(e, struct frame_entry, elem);
        if (entry->frame == frame) {
            entry->pin_status = true;
            break;
        }
    }
    lock_release(&ft_lock);
}

void ft_unpin(void *frame) {
    lock_acquire(&ft_lock);
    struct list_elem *e;
    for (e = list_begin(&ft); e != list_end(&ft); e = list_next(e)) {
        struct frame_entry *entry = list_entry(e, struct frame_entry, elem);
        if (entry->frame == frame) {
            entry->pin_status = false;
            break;
        }
    }
    lock_release(&ft_lock);
}

#endif 