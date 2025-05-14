#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
void syscall_init (void);
void halter();
void exiter(int status);
tid_t executer(void *esp);
tid_t waiter(void *esp);

int* get_paramater(void *esp,int offset);
void validate_ptr(const void* ptr);
#endif /* userprog/syscall.h */
