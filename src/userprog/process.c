#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#endif
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool tokenise(const char *cmdline, char **argv, int *argc);

static bool tokenise(const char *cmdline, char **argv, int *argc) {
  if (cmdline == NULL || argv == NULL || argc == NULL){
    return false;
  }

  char *token, *context;
  int i = 0;
  
  for (token = strtok_r((char *)cmdline, " ", &context); token != NULL; token = strtok_r(NULL, " \t\n", &context)) 
  {
    if (i >= MAX_ARGS){
      return false;
    }
    argv[i++] = token;
  }
  *argc = i;
  return (i > 0);
}

// returns pointer to file correspopnding to fd
struct file *get_file(int fd) {
  struct thread *cur = thread_current();
  struct list *fds = &cur->fds;
  struct list_elem *e;
  // Iterate through file descriptors to find file
  for (e = list_begin(fds); e != list_end(fds); e = list_next(e)) {
    struct file_descriptor *fd_entry = list_entry(e, struct file_descriptor, elem);
    if (fd_entry->fd == fd) {
      return fd_entry->file;
    }
  }
  // Not found, iterate through memory mapped files
  for (e = list_begin(&cur->memmapped_files); e != list_end(&cur->memmapped_files); e = list_next(e)) {
    struct memmapped_file *mmf = list_entry(e, struct memmapped_file, elem);
    if (mmf->mapid == fd) {
      return mmf->file;
    }
  }
  return NULL;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Extract args */
  char *argv[MAX_ARGS];
  int argc;
  if (!tokenise(fn_copy, argv, &argc)){
    // Malformed input, free page and return TID_ERROR
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (argv[0], PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  struct thread *cur = thread_current();
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  // Initialize interrupt frame and load executable. */
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  // If load failed, quit.
  palloc_free_page (file_name);
  if (!success){
    sema_up(&cur->exec_sema); // Wake up parent
    thread_exit ();
  }
  cur->succ = true;
  sema_up(&cur->exec_sema); // Wake up parent

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

static bool check_child_present(struct thread *cur, struct list_elem *elem) {
  struct list_elem *e;
  for (e = list_begin(&cur->c_list); e != list_end(&cur->c_list); e = list_next(e)) {
    if (e == elem) {
      return true;
    }
  }
  return false;
}


/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) {
  // Find child thread
  
  struct thread *cur = thread_current();
  //printf("PROCESS_WAIT DEBUG: Parent %d  waiting on Child: %d \n", cur->tid, child_tid);
  struct list_elem *e;
  struct thread *child = NULL;

    /* 
    {
      char buf[512];
      int len = 0;
      for (e = list_begin(&cur->c_list); e != list_end(&cur->c_list); e = list_next(e)) {
        struct thread *t = list_entry(e, struct thread, c_elem);
        len += snprintf(buf + len, sizeof(buf) - len, "tid %d at %p; ", t->tid, t);
      }
      PANIC("DEBUG: Parent %s c_list contains: %s", cur->name, buf);
    }*/
  

  for (e = list_begin(&cur->c_list); e != list_end(&cur->c_list); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, c_elem);
    if (t->tid == child_tid) {
      child = t;
      //PANIC("PROCESS_WAIT DEBUG: Parent %d found Child: %d \n", cur->tid, child_tid);
      break;
    }
  }
  if (child == NULL) {
    //PANIC("PROCESS_WAIT DEBUG: Parent %d has NULL Child \n", cur->tid);
    return -1;
  }

  if (child->waited) {
    //PANIC("PROCESS_WAIT DEBUG: Parent %d already waited on Child: %d \n", cur->tid, child_tid);
    return -1;
  }
  child->waited = true;
  
  int status = -1;
  // Wait for child to exit
  //PANIC("PROCESS_WAIT DEBUG: Parent %d waiting on sema_down(exit_sema) on Child: %d \n", cur->tid, child_tid);
  sema_down(&child->exit_sema);
  //PANIC("PROCESS_WAIT DEBUG: Parent %d fwoke after sema_down(exit_sema) on Child: %d \n", cur->tid, child_tid);
    /* Remove child from parent's c_list only if it is still present. */
    if (check_child_present(cur, &child->c_elem)) {
      status = child->exit_status;
      list_remove(&child->c_elem);
      //PANIC("PROCESS_WAIT DEBUG: Parent %d removed Child: %d \n", cur->tid, child_tid);
    } else {
      //PANIC("PROCESS_WAIT DEBUG: Parent %d Child not present in c_list: %d \n", cur->tid, child_tid);
    }
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current thread's page directory */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Set cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to original thread page directory.*/
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  /* Destroy SPT */
  #ifdef VM
  spt_destroy(&cur->spt);
  #endif
  /* Destroy maps */
  // handled in syscall_exit
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const void *file_name_);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  file_deny_write(file);
  t->executable = file;
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  #ifdef VM
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      // new spt entry for this page
      struct spt_entry *spte = malloc(sizeof(struct spt_entry));
      if (spte == NULL) {
        return false;
      }
      // switch to lazy loading
      spte->uvpage = upage;
      spte->write_protected = !writable;
      spte->file = file;
      spte->offset = ofs;
      spte->read_bytes = page_read_bytes;
      spte->zero_bytes = page_zero_bytes;
      spte->type = FILE_BACKED;
      spte->swap_index = (size_t)-1;
      spte->owner = thread_current();

      // insert entry into user thread's SPT
      bool succ = spt_insert(&thread_current()->spt, spte);
      if (!succ) {
        free(spte);
        return false;
      }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  #endif
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const void *file_name_) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){
        *esp = PHYS_BASE;
        uintptr_t esp_val = (uintptr_t) *esp;
        /* Expected stack Layout (from highest value addresses to lowest) (assuming esp is misaligned):
        * - argv[argc-1] to argv[0] - type char*
        * - padding - align esp
        * - sentinel - type void*
        * - &argv[argc-1] to &argv[0] - type char**
        * - argv - type char*
        * - argc - type int
        * - return address - type void (*)
        */
        // Get argv and argc
        char *argv[MAX_ARGS];
        int argc;
        // Make copy of file_name_
        char *fn_copy = malloc(strlen(file_name_) + 1);
        if (fn_copy == NULL) {
          // free page and return false
          palloc_free_page(kpage);
          return false;
        }
        strlcpy(fn_copy, file_name_, strlen(file_name_) + 1);
        if (!tokenise(fn_copy, argv, &argc)) {
          // free page and return false
          palloc_free_page(kpage);
          return false;
        }
        // push argv[argc-1] to argv[0] (strings)
        int i;
        char *argv_addr[MAX_ARGS];
        for (i = argc - 1; i >= 0; i--) {
          esp_val -= strlen(argv[i]) + 1;
          memcpy((void *)esp_val, argv[i], strlen(argv[i]) + 1);
          argv_addr[i] = (char *)esp_val;
        }
        // align esp
        // taken from https://stackoverflow.com/questions/19190502/how-do-i-check-a-memory-address-is-32-bit-aligned-in-c
        uintptr_t alignment = esp_val & 0x3;
        if (alignment != 0) {
          esp_val -= alignment;
        }
        // push sentinel
        esp_val -= sizeof(char*);
        *((char **)esp_val) = NULL;
        // push &argv[argc-1] to &argv[0] (addresses)
        for (i = argc - 1; i >= 0; i--) {
          esp_val -= sizeof(char*);
          *((char **)esp_val) = argv_addr[i];
        }
        // push argv, esp points to argv[0] in the stack by this line
        char **argv_ptr = (char **)esp_val;
        esp_val -= sizeof(char**);
        *((char ***)esp_val) = argv_ptr;
        
        // push argc
        esp_val -= sizeof(int);
        *(int *)esp_val = argc;
        // push return address
        esp_val -= sizeof(void*);
        *(void **)esp_val = NULL;
        // update esp
        *esp = (void *) esp_val;
      } else {
        palloc_free_page (kpage);
      }
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
