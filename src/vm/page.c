#ifdef VM
#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* hashes spt_entry based on VPN. */
static unsigned spt_hash(const struct hash_elem *e, void *aux UNUSED) {
    struct spt_entry *entry = hash_entry(e, struct spt_entry, spt_elem);
    return hash_int((int) entry->uvpage);
  }
  
/* Comparision function for hash table; true if pts_entry a has lower VPN than b */
static bool spt_comp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct spt_entry *entry_a = hash_entry(a, struct spt_entry, spt_elem);
    struct spt_entry *entry_b = hash_entry(b, struct spt_entry, spt_elem);
    return entry_a->uvpage < entry_b->uvpage;
}

/* Intialise hash table */
void spt_init(struct hash *spt) {
  hash_init(spt, spt_hash, spt_comp, NULL);
}

/* Inserts entry into spt
   Return true on success. */
bool spt_insert(struct hash *spt, struct spt_entry *entry) {
  entry->uvpage = pg_round_down(entry->uvpage);
  return hash_insert(spt, &entry->spt_elem) == NULL;
}

/* Retrieve spt_entry corresponding to uvpage from spt . */
struct spt_entry * spt_retrieve(struct hash *spt, void *uvpage) {
  struct spt_entry entry;
  entry.uvpage = uvpage;
  struct hash_elem *e = hash_find(spt, &entry.spt_elem);
  if (e != NULL) {
    return hash_entry(e, struct spt_entry, spt_elem);
  }
  return NULL;
}

static void spt_entry_destroy(struct hash_elem *e, void *aux UNUSED) {
  struct spt_entry *entry = hash_entry(e, struct spt_entry, spt_elem);
  free(entry);
}

void set_swap_index(struct spt_entry *spte, size_t swap_index) {
    spte->swap_index = swap_index;
}

/* Free all hash table resources. */
void spt_destroy(struct hash *spt) {
    hash_destroy(spt, spt_entry_destroy);
}

#endif