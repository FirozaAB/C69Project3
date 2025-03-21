#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "lib/stdio.h" 
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"


static void syscall_handler (struct intr_frame *);

static bool validate_pointer(const void *pointer){ // less robust than project2, page faults handle addresses on swap.
  return pointer != NULL && is_user_vaddr(pointer);
}

#ifdef VM
// create mapping between file and process memory
static int syscall_map(int fd, void *addr){
  struct thread *cur = thread_current();
  struct file *f = get_file(fd);
  if (f == NULL){
    return -1;
  }
  // validate addr
  if (!is_user_vaddr(addr) || addr == NULL || pg_ofs(addr) != 0){
    return -1;
  }
  // use file_reopen to avoid concurrency issues
  struct file *f_reopen = file_reopen(f);
  if (f_reopen == NULL){
    return -1;
  }
  off_t length = file_length(f_reopen);
  if (length == 0){
    file_close(f_reopen);
    return -1;
  }
  // create new memmapped_file struct
  struct memmapped_file *mmf = malloc(sizeof(struct memmapped_file));
  if (mmf == NULL){
    file_close(f_reopen);
    return -1;
  }
  //cur->curr_map++;
  mmf->mapid = cur->curr_map + 1;
  mmf->file = f_reopen;
  mmf->addr = addr;
  mmf->length = length;
  // add to list of memmapped_files for calling thread
  list_push_back(&cur->memmapped_files, &mmf->elem);
  // map pages
  off_t offset = 0;
  while (offset < length){
    void *upage = addr + offset;
    size_t read;
    if (length - offset >= PGSIZE){
      read = PGSIZE;
    } else {
      read = length - offset;
    }
    size_t zero = PGSIZE - read;
    // create new spt_entry for this page 
    struct spt_entry *spte = malloc(sizeof(struct spt_entry));
    if (spte == NULL){
      file_close(f_reopen);
      return -1;
    }
    // populate spt_entry, insert into spt (lazy loading)
    spte->uvpage = upage;
    spte->write_protected = false;
    spte->file = f_reopen;
    spte->offset = offset;
    spte->read_bytes = read;
    spte->zero_bytes = zero;
    spte->type = FILE_BACKED;
    spte->mapped = true;
    spte->owner = cur;
    if (!spt_insert(&cur->spt, spte)){
      free(spte);
      file_close(f_reopen);
      return -1;
    }
    // for next iteration, advance offset
    offset += read;
  }
  cur->curr_map++;
  return mmf->mapid;
}


// delete mapping between file and process memory
static void syscall_munmap(int mapid){
  struct thread *cur = thread_current();
  struct list_elem *e = list_begin(&cur->memmapped_files);
  while (e != list_end(&cur->memmapped_files)){
    struct memmapped_file *mmf_entry = list_entry(e, struct memmapped_file, elem);
    if (mmf_entry->mapid == mapid || mapid == -1){
      e = list_remove(e);
      // write back to file if dirty
      off_t offset = 0;
      while (offset < mmf_entry->length){
        void *upage = (char *)mmf_entry->addr + offset;
        struct spt_entry *spte = spt_retrieve(&cur->spt, upage);
        if (pagedir_is_dirty(cur->pagedir, upage)){
          file_write_at(spte->file, upage, spte->read_bytes, spte->offset);
        }
        // remove from thread's spt
        spt_remove(&cur->spt, spte);
        free(spte);
        offset += PGSIZE;
      }
      file_close(mmf_entry->file);
      free(mmf_entry);
    } else {
      e = list_next(e);
    }
  }
}
#endif

static tid_t syscall_exec(const char *cmd_line){
  tid_t tid = process_execute(cmd_line);
  /* Once child loads user program it will wake parent thread*/
  // Find child thread
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct thread *child = NULL;
  for (e = list_begin(&cur->c_list); e != list_end(&cur->c_list); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, c_elem);
    if (t->tid == tid) {
      child = t;
      break;
    }
  }
  if (child == NULL) {
    return -1;
  }
  // Wait for child to load
  sema_down(&child->exec_sema);
  if (!child->succ){
    return -1;
  }
  return tid;
}

static void close_open_fds(void){
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  while (!list_empty(fds)) {
    struct file_descriptor *fd_entry = list_entry(list_pop_front(fds), struct file_descriptor, elem);
    file_close(fd_entry->file);
    free(fd_entry);
  }
}

/* Allow exiting thread's executable to be written to*/
static int allow_write(void){
  struct thread *cur = thread_current();
  if (cur->executable != NULL){
    file_allow_write(cur->executable);
    return 1;
  }
  return 0;
}

/* Cleans up thread resources before calling thread_exit*/
static void syscall_exit(int status){
  struct thread *cur = thread_current();
  cur->exit_status = status;
  close_open_fds();
  if (allow_write()){
    file_close(cur->executable);
  }
  // close maps
  #ifdef VM
  syscall_munmap(-1);
  #endif
  printf ("%s: exit(%d)\n", thread_name(), status);
  // wake up parent
  sema_up(&cur->exit_sema);
  thread_exit();
}

static int syscall_wait(tid_t tid){
  tid_t child_tid = process_wait(tid);
  return child_tid;
}

static bool syscall_create(const char *file, unsigned initial_size){
  bool success = filesys_create(file, initial_size);
  return success;
}

static bool syscall_remove(const char *file){
  bool success = filesys_remove(file);
  return success;
}

static int syscall_open(const char *file){
  struct file *f = filesys_open(file);
  if (f == NULL){
    return -1;
  }
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
  if (fd == NULL){
    return -1;
  }
  fd->file = f;
  fd->fd = cur->fd_count;
  cur->fd_count++;
  list_push_back(fds, &fd->elem);
  return fd->fd;
}

static int syscall_read(int fd, void *buff, unsigned size){
  if (fd == 0){
    unsigned i;
    for (i = 0; i < size; i++){
      char c = input_getc();
      if (c == '\0'){
        return i;
      }
      *(char *)(buff + i) = c;
    }
    return size;
  }
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  struct list_elem *e;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)){
    struct file_descriptor *fd_entry = list_entry(e, struct file_descriptor, elem);
    if (fd_entry->fd == fd){
      return file_read(fd_entry->file, buff, size);
    }
  }
  return -1;
}

static int syscall_filesize(int fd){
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  struct list_elem *e;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)){
    struct file_descriptor *fd_entry = list_entry(e, struct file_descriptor, elem);
    if (fd_entry->fd == fd){
      return file_length(fd_entry->file);
    }
  }
  return -1;
}

static int syscall_write(int fd, const void *buff, unsigned size){
  if (fd == 1){
    putbuf(buff, size);
    return size;
  }
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  struct list_elem *e;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)){
    struct file_descriptor *fd_entry = list_entry(e, struct file_descriptor, elem);
    if (fd_entry->fd == fd){
      return file_write(fd_entry->file, buff, size);
    }
  }
  return -1;
}



static int syscall_seek(int fd, unsigned position){
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  struct list_elem *e;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)){
    struct file_descriptor *fd_entry = list_entry(e, struct file_descriptor, elem);
    if (fd_entry->fd == fd){
      file_seek(fd_entry->file, position);
      return 0;
    }
  }
  return -1;
}

static int syscall_tell(int fd){
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  struct list_elem *e;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)){
    struct file_descriptor *fd_entry = list_entry(e, struct file_descriptor, elem);
    if (fd_entry->fd == fd){
      return file_tell(fd_entry->file);
    }
  }
  return -1;
}

static int syscall_close(int fd){
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  struct list_elem *e;
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)){
    struct file_descriptor *fd_entry = list_entry(e, struct file_descriptor, elem);
    if (fd_entry->fd == fd){
      file_close(fd_entry->file);
      list_remove(e);
      free(fd_entry);
      return 0;
    }
  }
  return -1;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static char *extract_string_from_stack(struct intr_frame *f, int offset){
  return *(char **)((uint8_t *)f->esp + offset);
}

static int extract_int_from_stack(struct intr_frame *f, int offset){
  return *(int *)((uint8_t *)f->esp + offset);
}

static void
syscall_handler (struct intr_frame *f) {
  thread_current()->esp_copy = f->esp; // in case of page faults, save original esp
  // Validate syscall_no pointer
  if (!validate_pointer(f->esp)){
    syscall_exit(-1);
  }

  int syscall_no = extract_int_from_stack(f, 0);
  // call corresponding syscall function
  // args are validated contiguously
  switch (syscall_no) {
    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_EXIT:
      if (validate_pointer((uint8_t *)f->esp + 4)){
        syscall_exit(extract_int_from_stack(f, 4));
      } else {
        syscall_exit(-1);
      }
      break;

    case SYS_EXEC: {
      void *arg_ptr = (uint8_t *)f->esp + 4;
      if (validate_pointer(arg_ptr)) {
        char *cmd_line = extract_string_from_stack(f, 4);
        if (validate_pointer(cmd_line)){
          f->eax = syscall_exec(cmd_line);
        } else {
          syscall_exit(-1);
        }
      } else {
        syscall_exit(-1);
      }
      break;
    }

    case SYS_WAIT:
      if (validate_pointer((uint8_t *)f->esp + 4)){
        f->eax = syscall_wait(extract_int_from_stack(f, 4));
      } else {
        syscall_exit(-1);
      }
      break;

    case SYS_CREATE: {
      void *arg_ptr1 = (uint8_t *)f->esp + 4;
      void *arg_ptr2 = (uint8_t *)f->esp + 8;
      if (validate_pointer(arg_ptr1) && validate_pointer(arg_ptr2)) {
        char *file = extract_string_from_stack(f, 4);
        if (validate_pointer(file)){
          f->eax = syscall_create(file, (unsigned)extract_int_from_stack(f, 8));
        } else {
          syscall_exit(-1);
        }
      } else {
        syscall_exit(-1);
      }
      break;
    }

    case SYS_REMOVE: {
      void *arg_ptr = (uint8_t *)f->esp + 4;
      if (validate_pointer(arg_ptr)) {
        char *file = extract_string_from_stack(f, 4);
        if (validate_pointer(file)){
          f->eax = syscall_remove(file);
        } else {
          syscall_exit(-1);
        }
      } else {
        syscall_exit(-1);
      }
      break;
    }

    case SYS_OPEN: {
      void *arg_ptr = (uint8_t *)f->esp + 4;
      if (validate_pointer(arg_ptr)) {
        char *file = extract_string_from_stack(f, 4);
        if (validate_pointer(file)){
          f->eax = syscall_open(file);
        } else {
          syscall_exit(-1);
        }
      } else {
        syscall_exit(-1);
      }
      break;
    }

    case SYS_READ: {
      void *arg_ptr1 = (uint8_t *)f->esp + 4;
      void *arg_ptr2 = (uint8_t *)f->esp + 8;
      void *arg_ptr3 = (uint8_t *)f->esp + 12;
      if (validate_pointer(arg_ptr1) && validate_pointer(arg_ptr2) &&
          validate_pointer(arg_ptr3)) {
        int fd = extract_int_from_stack(f, 4);
        void *buff = *(void **)((uint8_t *)f->esp + 8);
        unsigned size = extract_int_from_stack(f, 12);
        if (validate_pointer(buff)){
          f->eax = syscall_read(fd, buff, size);
        } else {
          syscall_exit(-1);
        }
      } else {
        syscall_exit(-1);
      }
      break;
    }

    case SYS_WRITE: {
      void *arg_ptr1 = (uint8_t *)f->esp + 4;
      void *arg_ptr2 = (uint8_t *)f->esp + 8;
      void *arg_ptr3 = (uint8_t *)f->esp + 12;
      if (validate_pointer(arg_ptr1) && validate_pointer(arg_ptr2) &&
          validate_pointer(arg_ptr3)) {
        int fd = extract_int_from_stack(f, 4);
        void *buff = *(void **)((uint8_t *)f->esp + 8);
        unsigned size = extract_int_from_stack(f, 12);
        if (validate_pointer(buff)){
          f->eax = syscall_write(fd, buff, size);
        } else {
          syscall_exit(-1);
        }
      } else {
        syscall_exit(-1);
      }
      break;
    }

    case SYS_FILESIZE:
      if (validate_pointer((uint8_t *)f->esp + 4)){
        f->eax = syscall_filesize(extract_int_from_stack(f, 4));
      } else {
        syscall_exit(-1);
      }
      break;

    case SYS_SEEK:
      if (validate_pointer((uint8_t *)f->esp + 4) && validate_pointer((uint8_t *)f->esp + 8)){
        f->eax = syscall_seek(extract_int_from_stack(f, 4), (unsigned)extract_int_from_stack(f, 8));
      } else {
        syscall_exit(-1);
      }
      break;
    
    case SYS_TELL:
      if (validate_pointer((uint8_t *)f->esp + 4)){
        f->eax = syscall_tell(extract_int_from_stack(f, 4));
      } else {
        syscall_exit(-1);
      }
      break;
    
    case SYS_CLOSE:
      if (validate_pointer((uint8_t *)f->esp + 4)){
        f->eax = syscall_close(extract_int_from_stack(f, 4));
      } else {
        syscall_exit(-1);
      }
      break;
    
    #ifdef VM
    case SYS_MMAP:
      if (validate_pointer((uint8_t *)f->esp + 4) && validate_pointer((uint8_t *)f->esp + 8)){
        int fd = extract_int_from_stack(f, 4);
        void *addr = *(void **)((uint8_t *)f->esp + 8);
        f->eax = syscall_map(fd, addr);
      } else {
        syscall_exit(-1);
      }
      break;
    
    case SYS_MUNMAP:
      if (validate_pointer((uint8_t *)f->esp + 4)){
        int mapid = extract_int_from_stack(f, 4);
        syscall_munmap(mapid);
      } else {
        syscall_exit(-1);
      }
      break;
    #endif
    default:
      printf("Unknown system call: %d\n", syscall_no);
      syscall_exit(-1);
      break;
  }
}
