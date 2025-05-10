#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
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
syscall_handler (struct intr_frame *f) 
{
  if (f==NULL ||f->esp == NULL ){
    thread_exit();
    return;
  }
  printf ("system call!\n");
  void *esp = f->esp;
  int syscall =*(int*)esp;

  if (syscall == SYS_HALT){
    shutdown_power_off();
  }

  else if (syscall == SYS_EXIT){
   int status = *(int *)(f->esp + 4);
   struct thread *cur = thread_current();
   cur->exit = status;  
   printf("%s: exit(%d)\n", cur->name, status);
   process_exit();
  }
  else if (syscall == SYS_EXEC){
    char *cmd_line = *(char **)(f->esp + 4);
    tid_t child_tid = process_execute(cmd_line);
    f->eax = child_tid;
  } 
  else if (syscall == SYS_WAIT){
    process_wait(*(int*) (f->esp+4));
  }
  else if (syscall == SYS_CREATE){
    //filesys_create();
  }
  else if (syscall == SYS_REMOVE){
    //filesys_remove();
  }
  else if (syscall == SYS_OPEN){
   // file_open();
  }
  else if (syscall == SYS_FILESIZE){
    //
  }
  else if (syscall == SYS_READ){
    //file_read();
  }
  else if (syscall == SYS_WRITE){
   // file_write();
  }
  else if (syscall == SYS_SEEK){
    //file_seek();
  }
  else if (syscall == SYS_TELL){
    //file_tell();
  }
  else if (syscall == SYS_CLOSE){
   // file_close(f);
  }
  thread_exit ();
}
