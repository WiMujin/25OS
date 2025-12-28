#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/process.h" 
#include <string.h> 
#include "devices/shutdown.h" 
#include "devices/input.h"    
#include "userprog/pagedir.h"

/* 사용자 스택의 하한선 (Pintos 기준 0x08048000) [cite: 154] */
#define STACK_BOTTOM 0x08048000  

static void syscall_handler (struct intr_frame *);
void get_argument(void *esp, int *argv, int count);
void check_address(void *addr);

/* 파일 시스템 동기화를 위한 전역 락 */
struct lock filesys_lock;

void
syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock); 
}

/* [주소 유효성 검사] 
   사용자 포인터가 유효한지 검사합니다. 
   1. NULL 포인터가 아니어야 함.
   2. 사용자 영역 주소여야 함 (PHYS_BASE 미만).
   3. 실제 매핑된 페이지여야 함. 
   [cite: 157, 160] */
void check_address (void *addr)
{
    struct thread *cur = thread_current();
    if (addr == NULL || !is_user_vaddr(addr) || addr < (void *)STACK_BOTTOM ||
        pagedir_get_page(cur->pagedir, addr) == NULL)
    {
        exit(-1);
    }
}

/* [인자 가져오기]
   스택에서 4바이트 단위로 인자를 가져옵니다. 
   인자를 읽어오는 메모리 주소 자체도 유효한지 검사해야 합니다. [cite: 180, 187] */
void
get_argument(void *esp, int *argv, int count)
{
    int *ptr = (int *)esp;
    for(int i = 0; i < count; i++)
    {
        ptr++; // 다음 인자 위치로 이동 (esp + 4, esp + 8 ...)
        check_address((void *)ptr); // 포인터 주소 유효성 검사
        argv[i] = *ptr; // 값 읽어오기
    }
}

/* --- File System Calls --- */

bool create(const char *file, unsigned initial_size)
{
    check_address((void *)file); // 파일 이름 포인터 검사
    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}

bool remove (const char *file)
{
    check_address((void *)file);
    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file);
    lock_release(&filesys_lock);
    return success;
}

int open (const char *file)
{
    check_address((void *)file);
    
    if (file == NULL) return -1;

    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    
    /* [실행 파일 쓰기 금지] 
       현재 실행 중인 스레드의 이름과 열려는 파일명이 같으면 쓰기를 막습니다.  */
    if (f != NULL && strcmp(thread_current()->name, file) == 0) {
        file_deny_write(f);
    }

    int fd = -1;
    if (f != NULL) {
        fd = process_add_file(f); // fd 테이블에 추가 (process.c 구현)
    }
    lock_release(&filesys_lock);

    return fd;
}

int filesize (int fd)
{
    struct file *f = process_get_file(fd);
    if (f == NULL) return -1;
    return file_length(f);
}

int read (int fd, void *buffer, unsigned size)
{
    check_address(buffer);
    /* 버퍼의 끝 주소도 검사하여 페이지 경계를 넘는 경우를 대비 */
    void *end_buffer = (char *)buffer + size - 1;
    check_address(end_buffer);

    lock_acquire(&filesys_lock);
    int read_byte = -1;

    /* STDIN 처리 [cite: 56] */
    if (fd == 0) 
    {
        unsigned i;
        char *buf = buffer;
        for (i = 0; i < size; i++)
        {
            char key = input_getc(); 
            *buf++ = key;
            if (key == '\0') break;
        }
        read_byte = i;
    }
    /* 일반 파일 읽기 */
    else if (fd > 1) 
    {
        struct file *f = process_get_file(fd);
        if (f != NULL) {
            read_byte = file_read(f, buffer, size);
        }
    }
    lock_release(&filesys_lock);
    return read_byte;
}

int write (int fd, const void *buffer, unsigned size)
{
    check_address((void *)buffer);
    void *end_buffer = (char *)buffer + size - 1;
    check_address(end_buffer);

    lock_acquire(&filesys_lock);
    int write_byte = -1;

    /* STDOUT 처리 [cite: 61] */
    if (fd == 1) 
    {
        putbuf(buffer, size);
        write_byte = size;
    }
    /* 일반 파일 쓰기 */
    else if (fd > 1) 
    {
        struct file *file = process_get_file(fd);
        if (file != NULL) {
            /* 파일 시스템이 고정 크기이므로 EOF 넘어서는 쓰기 불가 [cite: 60] */
            write_byte = file_write(file, buffer, size);
        }
    }
    lock_release(&filesys_lock);
    return write_byte;
}

void seek (int fd, unsigned position)
{
    struct file *file = process_get_file(fd);
    if (file != NULL) {
        lock_acquire(&filesys_lock);
        file_seek(file, position);
        lock_release(&filesys_lock);
    }
}

unsigned tell (int fd)
{
    struct file *file = process_get_file(fd);
    unsigned pos = 0;
    if (file != NULL) {
        lock_acquire(&filesys_lock);
        pos = file_tell(file);
        lock_release(&filesys_lock);
    }
    return pos;
}

void close (int fd)
{
    lock_acquire(&filesys_lock);
    process_close_file(fd); // process.c 구현
    lock_release(&filesys_lock);
}

/* --- Process System Calls --- */

void exit(int status)
{
    struct thread *cur = thread_current();
    cur->exit_status = status; 
    thread_exit(); 
}

void halt(void)
{
    shutdown_power_off(); 
}

int wait (pid_t pid)
{
    return process_wait(pid); // process.c 구현 [cite: 31]
}

pid_t exec (const char *file)
{
    check_address((void *)file);
    // process_execute 내부에서 로드 대기 및 동기화 수행 [cite: 13]
    return process_execute(file);
}

/* --- Main Handler --- */

void
syscall_handler (struct intr_frame *f) 
{
    /* 1. 스택 포인터(ESP) 유효성 검사 */
    check_address(f->esp); 

    int *argv = (int *)f->esp; // 인자 배열 포인터
    int syscall_number = argv[0]; // 시스템 콜 번호

    /* 2. 변수 일괄 선언 (Switch 문 내부 선언 금지) */
    struct thread *cur = thread_current();
    int fd;
    void *buffer;
    unsigned size;
    unsigned position;
    struct file *file;

    switch(syscall_number)
    {
        case SYS_HALT:
            halt();
            break;
            
        case SYS_EXIT:
            if (!is_user_vaddr((void *)(argv + 1))) exit(-1);
            exit(argv[1]);
            break;

        case SYS_EXEC:
            if (!is_user_vaddr((void *)(argv + 1))) exit(-1);
            f->eax = exec((const char *)argv[1]);
            break;
            
        case SYS_WAIT:
            if (!is_user_vaddr((void *)(argv + 1))) exit(-1);
            f->eax = wait((pid_t)argv[1]);
            break;

        case SYS_CREATE:
            // 인자: [1]filename, [2]initial_size
            if (!is_user_vaddr((void *)(argv + 2))) exit(-1);
            check_address((void *)argv[1]);
            
            if ((const char *)argv[1] == NULL) exit(-1);

            lock_acquire(&filesys_lock);
            f->eax = filesys_create((const char *)argv[1], (unsigned)argv[2]);
            lock_release(&filesys_lock);
            break;
            
        case SYS_REMOVE:
            if (!is_user_vaddr((void *)(argv + 1))) exit(-1);
            check_address((void *)argv[1]);
            
            if ((const char *)argv[1] == NULL) exit(-1);

            lock_acquire(&filesys_lock);
            f->eax = filesys_remove((const char *)argv[1]);
            lock_release(&filesys_lock);
            break;
        
        case SYS_OPEN:
            if (!is_user_vaddr((void *)(argv + 1))) exit(-1);
            check_address((void *)argv[1]);
            
            if ((const char *)argv[1] == NULL) exit(-1);

            lock_acquire(&filesys_lock);
            file = filesys_open((const char *)argv[1]);
            
            if (file == NULL) {
                f->eax = -1;
            } else {
                // 빈 FD 찾기 (2부터 시작)
                fd = 2;
                while (fd < 128) {
                    if (cur->fd_table[fd] == NULL) break;
                    fd++;
                }

                if (fd >= 128) {
                    file_close(file);
                    f->eax = -1;
                } else {
                    cur->fd_table[fd] = file;
                    if (fd >= cur->fd_max) cur->fd_max = fd + 1;
                    f->eax = fd;
                }
            }
            lock_release(&filesys_lock);
            break;
        
        case SYS_FILESIZE:
            if (!is_user_vaddr((void *)(argv + 1))) exit(-1);
            fd = argv[1];
            
            lock_acquire(&filesys_lock);
            if (fd >= 2 && fd < 128 && cur->fd_table[fd] != NULL) {
                f->eax = file_length(cur->fd_table[fd]);
            } else {
                f->eax = -1;
            }
            lock_release(&filesys_lock);
            break;

       case SYS_READ:
            // 인자: [1]fd, [2]buffer, [3]size
            if (!is_user_vaddr((void *)(argv + 3))) exit(-1);
            fd = argv[1];
            buffer = (void *)argv[2];
            size = argv[3];

            check_address(buffer);
            
            /* [수정] 버퍼의 끝 주소도 유효한지 검사 (bad-read2 해결용) */
            if (size > 0) 
            {
                check_address((char *)buffer + size - 1);
            }

            lock_acquire(&filesys_lock);

            if (fd == 0) { // STDIN
                unsigned i;
                uint8_t *buf = (uint8_t *)buffer;
                for (i = 0; i < size; i++) {
                    buf[i] = input_getc();
                }
                f->eax = size;
            } else if (fd >= 2 && fd < 128 && cur->fd_table[fd] != NULL) { // FILE
                f->eax = file_read(cur->fd_table[fd], buffer, size);
            } else {
                f->eax = -1;
            }
            lock_release(&filesys_lock);
            break;

        case SYS_WRITE:
            // 인자: [1]fd, [2]buffer, [3]size
            if (!is_user_vaddr((void *)(argv + 3))) exit(-1);
            fd = argv[1];
            buffer = (void *)argv[2];
            size = argv[3];

            check_address(buffer);
            
            /* [수정] 버퍼의 끝 주소도 유효한지 검사 (bad-write2 해결용) */
            if (size > 0) 
            {
                check_address((char *)buffer + size - 1);
            }

            lock_acquire(&filesys_lock);

            if (fd == 1) { // STDOUT
                putbuf((const char *)buffer, size);
                f->eax = size;
            } else if (fd >= 2 && fd < 128 && cur->fd_table[fd] != NULL) { // FILE
                f->eax = file_write(cur->fd_table[fd], buffer, size);
            } else {
                f->eax = 0; // 실패 시 0
            }
            lock_release(&filesys_lock);
            break;
            
        case SYS_SEEK:
            if (!is_user_vaddr((void *)(argv + 2))) exit(-1);
            fd = argv[1];
            position = argv[2];
            
            lock_acquire(&filesys_lock);
            if (fd >= 2 && fd < 128 && cur->fd_table[fd] != NULL) {
                file_seek(cur->fd_table[fd], position);
            }
            lock_release(&filesys_lock);
            break;

        case SYS_TELL:
            if (!is_user_vaddr((void *)(argv + 1))) exit(-1);
            fd = argv[1];
            
            lock_acquire(&filesys_lock);
            if (fd >= 2 && fd < 128 && cur->fd_table[fd] != NULL) {
                f->eax = file_tell(cur->fd_table[fd]);
            } else {
                f->eax = -1;
            }
            lock_release(&filesys_lock);
            break;

        case SYS_CLOSE:
            if (!is_user_vaddr((void *)(argv + 1))) exit(-1);
            fd = argv[1];
            
            lock_acquire(&filesys_lock);
            if (fd >= 2 && fd < 128 && cur->fd_table[fd] != NULL) {
                file_close(cur->fd_table[fd]);
                cur->fd_table[fd] = NULL;
            }
            lock_release(&filesys_lock);
            break;

        default:
            exit(-1);
    }
}