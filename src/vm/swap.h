#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>
#include <stdbool.h>

void swap_init(void);
size_t swap_out(void *frame);
void swap_in(size_t swap_index, void *frame);
void swap_free(size_t swap_index);

#endif 