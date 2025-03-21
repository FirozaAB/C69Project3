#ifndef VM_FRAME_H
#define VM_FRAME_H

#ifdef VM

#include <list.h>
#include <stdint.h>
#include <stdbool.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/page.h"

/* Frame Table Entry */
struct frame_entry {
    void *frame;                /* kernal vaddr for frame */
    void *page;                /* page-aligned user vaddr for linked page */
    struct thread *owner;       /* current owner of this frame */
    bool pin_status;             /* If false, this frame cannot be swapped out */
    struct list_elem elem;      /* List element for global frame table. */
};

void ft_init(void);
void *ft_allocate(void *page, bool pinned);
void ft_evict(void); /* Implements clock replacement algorithm */
void ft_free(void *frame); 
void ft_pin(void *frame); /* Set pin_status to true*/
void ft_unpin(void *frame); /* Set pin_status to false*/

#endif 
#endif 