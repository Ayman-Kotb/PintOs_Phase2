#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include <list.h>

static void syscall_handler (struct intr_frame *);
static struct lock file_lock;
int x = 0 ;
static bool isValid_ptr (const void* ptr){
  if (ptr>= (void*) 0xc0000000 || ptr < (void*) 0x8048000 ){
    return false;
  }
  return true;
} 
bool create(const char* file, unsigned initial_size){
  bool created = filesys_create(file, initial_size);
  return created;
}
static bool remove(const char* file){
  bool removed = filesys_remove(file);
  return removed;
}

struct opened_file {
  int file_d;
  struct file* f;
};
static struct lock file_lock;
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
  if (x==0)lock_init(&file_lock);
  x++;
  if (f==NULL ||f->esp == NULL ){
    thread_exit();
    return;
  }

  int syscall = *(int *) f->esp;
  if (syscall == SYS_HALT){
    halter();
  }
  else if (syscall == SYS_EXIT){
    exiter(f->esp);
  }
  else if (syscall == SYS_EXEC){
    f->eax = executer(f->esp);
  }
  else if (syscall == SYS_WAIT){
    int* tid = (int *)(f->esp + 4);
    if (!isValid_ptr((void*)tid)) return -1;
    else f->eax = process_wait(*(int*) (f->esp+4));
  }
  else if (syscall == SYS_CREATE){
    
    int fd = *((int *)(f->esp)+1);
    if (!isValid_ptr((void*)fd)) f->eax = 0;
    int size = *((int*)(f->esp)+2) ;
    lock_acquire(&file_lock);
    bool created = create((char*) fd, size);
    lock_release(&file_lock);
    f->eax = created;
    //filesys_create();
  }
  else if (syscall == SYS_REMOVE){
    int fd = *((int *)(f->esp)+1);
    if (!isValid_ptr((void*)fd)) f->eax = 0;
    lock_acquire(&file_lock);
    bool removed = remove((char*)fd);
    lock_release(&file_lock);
    f->eax = (removed==true) ? 1 : 0 ;
  }
  else if (syscall == SYS_OPEN){

   // file_open();
  }
  else if (syscall == SYS_FILESIZE){
    
  }
  else if (syscall == SYS_READ){
    int stream = get_paramater(f->esp,4);
    const void *bfr = (void *) get_paramater(f->esp,8);
    unsigned size = get_paramater(f->esp,12);

    if (stream == 0) {
      for (unsigned i = 0; i < size; i++) {
        ((char *)bfr)[i] = input_getc();
      }
      f->eax = size;
    }
    //file_read();
  }
  else if (syscall == SYS_WRITE){
    int fd = *(int *)(f->esp +4);
    const void *buffer = (void *) *(int *)(f->esp+8);
    unsigned size = *(int *)(f->esp + 12);
    if (fd == 1) {
      putbuf(buffer, size);
      f->eax = size;
    } 
   
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
}
void validate_ptr(const void *ptr){
  if(ptr==NULL||!is_user_vaddr(ptr)) thread_exit();
 
}
int get_paramater(void *esp,int offset){
  return *(int *)(esp + offset);
}

void halter(){
    shutdown_power_off();
}

void exiter(void *esp){
   int status = get_paramater(esp,4);
   struct thread *cur = thread_current();
   cur->status_exit = status; 
   printf("%s: exit(%d)\n", thread_current()->name, status); 
   thread_exit();
}
tid_t executer(void* esp){
    char *cmd_line = (char *) get_paramater(esp,4);
    return process_execute(cmd_line);   
}
tid_t waiter(void* esp){
    return process_wait(*(int*) (esp+4));
}