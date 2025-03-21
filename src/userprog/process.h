#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#define MAX_ARGS 32
#define MAX_ARG_LENGTH 128

#include "threads/thread.h"

struct memmapped_file {
  int mapid; // mapid
  struct file *file; // mapped file
  void *addr; // start address
  off_t length; // length of mapped file
  struct list_elem elem; // list element
};


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct file *get_file(int fd);

#endif /* userprog/process.h */
