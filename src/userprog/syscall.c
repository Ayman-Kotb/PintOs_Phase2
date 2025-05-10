#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
// SYS_HALT,                   /* Halt the operating system. */
  // SYS_EXIT,                   /* Terminate this process. */
  // SYS_EXEC,                   /* Start another process. */
  // SYS_WAIT,                   /* Wait for a child process to die. */
  // SYS_CREATE,                 /* Create a file. */
  // SYS_REMOVE,                 /* Delete a file. */
  // SYS_OPEN,                   /* Open a file. */
  // SYS_FILESIZE,               /* Obtain a file's size. */
  // SYS_READ,                   /* Read from a file. */
  // SYS_WRITE,                  /* Write to a file. */
  // SYS_SEEK,                   /* Change position in a file. */
  // SYS_TELL,                   /* Report current position in a file. */
  // SYS_CLOSE 
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (f==NULL ||f->esp == NULL ){
    return;
  }
  
  printf ("system call!\n");
  int args[3];
  int syscall =*(int*) f->esp;
  if (syscall == SYS_HALT){
    shutdown_power_off();
  }
  else if (syscall == SYS_EXIT){
   process_exit();
  }
  else if (syscall == SYS_EXEC){
    
  } 
  else if (syscall == SYS_WAIT){
    process_wait(*(int*) (f->esp+4));
  }
  else if (syscall == SYS_CREATE){
    
  }
  else if (syscall == SYS_REMOVE){
    
  }
  else if (syscall == SYS_OPEN){
    
  }
  else if (syscall == SYS_FILESIZE){
    
  }
  else if (syscall == SYS_READ){
    
  }
  else if (syscall == SYS_WRITE){
    
  }
  else if (syscall == SYS_SEEK){
    
  }
  else if (syscall == SYS_TELL){
    
  }
  else if (syscall == SYS_CLOSE){

  }
  thread_exit ();
}
