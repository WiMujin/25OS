#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void exit (int status); // process.c 등에서 호출 가능하도록

#endif /* userprog/syscall.h */