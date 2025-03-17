#ifndef VM_PAGE_H
#define VM_PAGE_H

#ifdef VM

#include <list.h>
#include <stdint.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "lib/kernel/hash.h"

/* Supplemental Page Table Entry */
struct spt_entry {
    struct hash_elem spt_elem;            /* Hash element for SPT hash table */
    void *uvpage;                /* User-level Virtual Page Address. */
    bool write_protected;              /* protection flag */
    enum { 
        FILE_BACKED, 
        SWAP, 
        ZERO } type;  
    /* File-backed pages. */
    struct file *file;          /* File pointer. */
    off_t offset;               /* Data start offset. */
    uint32_t read_bytes;        /* read bytes */
    uint32_t zero_bytes;        /* padded bytes */
    /* Swapped pages. */
    size_t swap_index;          /* Swap Table index. */
};

void spt_init(struct hash *spt);
bool spt_insert(struct hash *spt, struct spt_entry *entry);
struct spt_entry * spt_retrieve(struct hash *spt, void *uvpage) ;
void spt_destroy(struct hash *spt);
void set_swap_index(struct spt_entry *spte, size_t swap_index);

#endif /* VM */

#endif /* VM_PAGE_H */