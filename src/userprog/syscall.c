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

static void syscall_handler (struct intr_frame *);
static struct lock file_lock;
int x = 0 ;
static bool isValid_ptr (const void* ptr){
  if(!is_user_vaddr(ptr)||lookup_page(thread_current()->pagedir,ptr,false)==NULL) return false;
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
   
    exiter(*get_paramater(f->esp,4));
  }
  else if (syscall == SYS_EXEC){
    f->eax = executer(f->esp);
  }
  else if (syscall == SYS_WAIT){
    int* tid = get_paramater(f->esp,4);
    if (!isValid_ptr((void*)tid)) return -1;
    else f->eax = process_wait(*(int*) (f->esp+4));
  }
  else if (syscall == SYS_CREATE){
    
    int fd = *((int *)(f->esp)+1);
    char* fdc = (char *) *get_paramater(f->esp,4);
    if (!isValid_ptr((void*)fd)) exiter(-1);
    
      int size = *((int*)(f->esp)+2) ;
      lock_acquire(&file_lock);
      bool created = create((char*) fd, size);
      lock_release(&file_lock);
      f->eax = created;  
    
    
    //filesys_create();
  }
  else if (syscall == SYS_REMOVE){
    int fd = *((int *)(f->esp)+1);
    char* fdc = (char *) *get_paramater(f->esp,4);
    if (!isValid_ptr((void*)fd)) exiter(-1);
    
      lock_acquire(&file_lock);
      bool removed = remove((char*)fd);
      lock_release(&file_lock);
      f->eax = removed ;
    
    
  }
  else if (syscall == SYS_OPEN) {
    // Get filename argument from stack
    const char *file = *(const char **)(f->esp + 4);
  
    // Call your implementation
    f->eax = open(file);
}
  else if (syscall == SYS_FILESIZE){
    int file_d=*get_paramater(f->esp,4);
    if(file_d<2||file_d>128|| thread_current()->fd_table[file_d] == NULL){
      f->eax=-1;   
      return;
    } 
    lock_acquire(&file_lock);
    f->eax=file_length(thread_current()->fd_table[file_d]);
    lock_release(&file_lock);
  }
  else if (syscall == SYS_READ){
  
    int fd = *get_paramater(f->esp,4);
    void *bfr = (void *) *get_paramater(f->esp,8);
    if (!isValid_ptr(bfr)) exiter(-1);
    unsigned size = *get_paramater(f->esp,12);
    
    if(fd<0||fd>=128) return;
    if (fd == 0) {
      for (unsigned i = 0; i < size; i++) {
        lock_acquire(&file_lock);
        ((char *)bfr)[i] = input_getc();
        lock_release(&file_lock);
      }
      f->eax = size;
    }
    else if(fd==1){
      // negative area 
    }
    else{
       struct file *file = thread_current()->fd_table[fd];
        if (!file) {
            f->eax = -1;
            return;
        }
        lock_acquire(&file_lock);
        f->eax = file_read(file, bfr, size); // Correct read
        lock_release(&file_lock);
    }
  }
  else if (syscall == SYS_WRITE){
    int file_d = *get_paramater(f->esp,4);
    const void *bfr = (void *) *get_paramater(f->esp,8);
    if (!isValid_ptr(bfr)) exiter(-1);
    unsigned size = *get_paramater(f->esp,12);
    if(file_d<0||file_d>=128) return;
    if (file_d == 1) {
      lock_acquire(&file_lock);
      putbuf(bfr, size);
      lock_release(&file_lock);
      f->eax = size;
    } 
    else if(file_d==0){
      // negative area
    }
    else{
      struct file* file=thread_current()->fd_table[file_d];
      if(file==NULL) return -1;
      lock_acquire(&file_lock);   
      size=file_write(file,bfr,size);   
      lock_release(&file_lock);
      f->eax=size; 
    }

   
  }
  else if (syscall == SYS_SEEK){
    seek(f->esp);
  }
  else if (syscall == SYS_TELL){
    //file_tell();
  }
  else if (syscall == SYS_CLOSE){
    int fd = *(int *)(f->esp + 4);
    if (fd < 2 || fd >= 128)
    return;
    
  struct thread *curr = thread_current();
  
  // Check if the file descriptor is actually in use
  if (curr->fd_table[fd] == NULL)
    return;
    
  // Acquire the filesystem lock to prevent race conditions
  lock_acquire(&file_lock);
  
  // Close the file
  file_close(curr->fd_table[fd]);
  
  // Clear the file descriptor entry
  curr->fd_table[fd] = NULL;
  
  // Release the filesystem lock
  lock_release(&file_lock);

  }
}
void validate_ptr(const void *ptr){
  if(ptr==NULL||!is_user_vaddr(ptr)) thread_exit();
 
}
int* get_paramater(void *esp,int offset){
  if (!isValid_ptr((int *)(esp + offset))) exiter(-1);
  return (int *)(esp + offset);
}

void halter(){
    shutdown_power_off();
}
void seek(void* esp){
int file_d = *get_paramater(esp,4);
  struct file* file=thread_current()->fd_table[file_d];
  int offset=*get_paramater(esp,8);
  lock_acquire(&file_lock);
  file_seek(file,offset);
  lock_release(&file_lock);
}


void exiter(int status){
   struct thread *cur = thread_current();
   cur->parent->status_exit = status; 
   printf("%s: exit(%d)\n", thread_current()->name, status); 
   thread_exit();
}
tid_t executer(void* esp){
    char *cmd_line = (char *) *get_paramater(esp,4);
    if (!isValid_ptr((void*) cmd_line)) return -1 ;
    return process_execute(cmd_line);   
}
tid_t waiter(void* esp){
    return process_wait(*(int*) (esp+4));
}

int open(const char *file) {
  // Check for null pointer
  if (file == NULL)
    return -1;
  
  // Get current thread
  struct thread *curr = thread_current();
  
  // Acquire the filesystem lock to prevent race conditions
  lock_acquire(&file_lock);
  
  // Open the file using the PintOS filesystem
  struct file *file_ptr = filesys_open(file);
  
  // Release the filesystem lock
  lock_release(&file_lock);
  
  // Check if the file was opened successfully
  if (file_ptr == NULL)
    return -1;
    
  // Find an available file descriptor
  int fd;
  for (fd = 2; fd < 128; fd++) {
    if (curr->fd_table[fd] == NULL) {
      curr->fd_table[fd] = file_ptr;
      return fd;
    }
  }
  
  return -1;
}
