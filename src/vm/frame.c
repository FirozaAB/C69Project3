#ifdef VM
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

static struct list ft; /* Frame Table */
static struct lock ft_lock; /* Frame Table Lock */
static struct list_elem *clock; /* Clock Hand. Defined as global to improve efficiency */
static bool clock_init = false; /* Clock Hand init flag */

void ft_init(void) {
    list_init(&ft);
    lock_init(&ft_lock);
    clock = NULL;
}

// Allocate a frame for a page, evicting a frame if necessary.
// If pinned is true, the frame will not be evicted.
void *ft_allocate(void *page, bool pinned) {
    int page_flag = PAL_USER;
    if (pinned) {
        page_flag |= PAL_PINNED;
    }
    void *frame = palloc_get_page(page_flag);
    while (frame == NULL) {
        ft_evict();
        frame = palloc_get_page(page_flag);
    }
    struct frame_entry *entry = malloc(sizeof(struct frame_entry));
    if (entry == NULL) {
        palloc_free_page(frame);
        return NULL;
    }
    entry->frame = frame;
    entry->page = page;
    entry->owner = thread_current();
    if(pinned) {
        entry->evictable = false;
    } else {
        entry->evictable = true;
    }
    lock_acquire(&ft_lock);
    if (!clock_init) {
        clock = list_begin(&ft);
        clock_init = true;
    }
    list_push_back(&ft, &entry->elem);
    lock_release(&ft_lock);
    return frame;
}

// Retrieve the frame entry corresponding to a frame.
void ft_free(void *frame) {
    lock_acquire(&ft_lock);
    struct list_elem *e;
    for (e = list_begin(&ft); e != list_end(&ft); e = list_next(e)) {
        struct frame_entry *entry = list_entry(e, struct frame_entry, elem);
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
// If the frame is pinned, it will not be evicted.
void ft_evict(void) {
    lock_acquire(&ft_lock);
    while (true) {
        if (clock == NULL) {
            clock = list_begin(&ft);
        }
        if (clock == list_end(&ft)) {
            clock = list_begin(&ft);
            if (clock == list_end(&ft)) { // No frames to evict
                lock_release(&ft_lock);
                PANIC("SPT: No frames to evict.");
                break;
            }
        }
        struct frame_entry *entry = list_entry(clock, struct frame_entry, elem);
        if (entry->evictable) {
            if (pagedir_is_accessed(entry->owner->pagedir, entry->page)) { // second chance
                pagedir_set_accessed(entry->owner->pagedir, entry->page, false);
            } else { // evict
                // get victim frame
                struct spt_entry *spte = spt_retrieve(&entry->owner->spt, entry->page);
                assert(spte != NULL);
                if (pagedir_is_dirty(entry->owner->pagedir, entry->page)) {
                    if (spte->type == SWAP || spte->type == ZERO) {
                        spte->swap_index = swap_out(entry->frame);
                        spte->type = SWAP;
                    } else if (spte->type == FILE_BACKED) {
                        if(spte->file == NULL){
                            spte->swap_index = swap_out(entry->frame);
                            spte->type = SWAP;
                        } else {
                            spte->type = FILE_BACKED;
                            file_write_at(spte->file, entry->frame, spte->read_bytes, spte->offset);
                        }
                    } else {
                        PANIC("SPT: Invalid spte type.\n");
                    }
                }
                // free frame, and advnace clock
                pagedir_clear_page(entry->owner->pagedir, entry->page);
                struct list_elem *next = list_next(clock);
                list_remove(clock);
                clock = next;
                palloc_free_page(entry->frame);
                free(entry);
                break;
            }
        }
        clock = list_next(clock);
    }
    lock_release(&ft_lock);
}

#endif 