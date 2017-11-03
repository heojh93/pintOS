#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "vm/page.h"

void syscall_init (void);
struct lock filesys_lock;

struct vm_entry *check_address (void *addr, void *esp /*Unused*/);
void check_valid_buffer (void *buffer, unsigned size, void *esp, bool to_write);
void check_valid_string (const void *str, void *esp);
void get_argument (void *esp, int *arg, int count);
#endif /* userprog/syscall.h */
