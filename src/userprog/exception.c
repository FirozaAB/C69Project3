#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/process.h"
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h" 
#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#endif

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));
  intr_enable ();
  page_fault_cnt++;
  not_present = (f->error_code & PF_P) == 0;
  user = (f->error_code & PF_U) != 0;


  
  /* Illegal cases; page present and invaid access, or attempted kernel space access*/
  if (!not_present || !is_user_vaddr(fault_addr) || fault_addr == NULL) {
    kill (f);
    return;
  }

  #ifdef VM
  void *vpn = pg_round_down(fault_addr);
  // Retrieve the supplemental page table entry
  struct spt_entry *spte = spt_retrieve(&thread_current()->spt, vpn);
  // NULL SPTe; caused by 1) stack growth 2) invalid access
  if (spte == NULL) {
    void *stack_ptr;
    void *stack_limit = PHYS_BASE - 8 * 1024 * 1024; // 8MB stack limit
    if (user){
      stack_ptr = f->esp;
    } else {
      stack_ptr = thread_current()->esp_copy;
    }
    if (fault_addr >= stack_ptr - 32 && fault_addr < PHYS_BASE && fault_addr >= stack_limit) {
      // Fault address is within stack growth threshold (32 bytes from esp)
      struct spt_entry *new_spte = malloc(sizeof(struct spt_entry));
      if (new_spte == NULL) {
        kill(f);
        return;
      }
      new_spte->uvpage = pg_round_down(fault_addr);
      new_spte->write_protected = false;
      new_spte->file = NULL;
      new_spte->swap_index = -1;
      new_spte->type = ZERO;
      new_spte->offset = 0;
      new_spte->read_bytes = 0;
      new_spte->zero_bytes = PGSIZE;
      new_spte->owner = thread_current();
      bool succ = spt_insert(&thread_current()->spt, new_spte);
      if (!succ) {
        free(new_spte);
        kill(f);
        return;
      }
      spte = new_spte;
    } else { // invalid access, terminate thread
      kill(f);
      return;
    }
  }
  void *frame = ft_allocate(spte->uvpage, true); // pin to avoid eviction during allocation process
  if (frame == NULL) {
    kill(f);
    return;
  }
  switch(spte->type) {
    case FILE_BACKED:
      if(spte->file == NULL) {
        kill(f);
        return;
      }
      if (!spte->mapped) { // standard file
        file_seek(spte->file, spte->offset);
        if (file_read(spte->file, frame, spte->read_bytes) != (int) spte->read_bytes) {
          ft_free(frame);
          kill(f);
          return;
        }
      } else { // memory mapped file
        if (file_read_at(spte->file, frame, spte->read_bytes, spte->offset) != (int) spte->read_bytes) {
          ft_free(frame);
          kill(f);
          return;
        }
      }
      memset(frame + spte->read_bytes, 0, spte->zero_bytes); // zero out remaining bytes
      break;
    case SWAP:
      swap_in(spte->swap_index, frame);
      break;
    case ZERO:
      memset(frame, 0, PGSIZE);
      break;
    default:
      kill(f);
      return;
  }
 
  // read page into frame
  if (!pagedir_set_page(thread_current()->pagedir, spte->uvpage, frame, !spte->write_protected)) {
    ft_free(frame);
    kill(f);
    return;
  }
  // unpin the frame
  ft_unpin(frame);
  #else
  bool write;        /* True: access was write, false: access was read. */
  write = (f->error_code & PF_W) != 0;
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  #endif
}

