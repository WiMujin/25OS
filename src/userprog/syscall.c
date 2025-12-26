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

static void
syscall_handler (struct intr_frame *f) 
{
    /* 1. 스택 포인터(ESP) 자체 유효성 검사 */
    check_address(f->esp); 

    int syscall_number = *(int *)f->esp;
    int argv[3]; // 인자는 최대 3개까지 사용됨

    switch(syscall_number)
    {
        case SYS_HALT:
            halt();
            break;
            
        case SYS_EXIT:
            get_argument(f->esp, argv, 1);
            exit(argv[0]);
            break;

        case SYS_EXEC:
            get_argument(f->esp, argv, 1);
            // exec 구현 전이면 -1 리턴하거나 주석 처리
            f->eax = exec((const char *)argv[0]);
            break;
            
        case SYS_WAIT:
            get_argument(f->esp, argv, 1);
            // wait 구현 전이면 -1 리턴하거나 주석 처리
            f->eax = wait((pid_t)argv[0]);
            break;

        /* --- [수정됨] CREATE 구현 --- */
        case SYS_CREATE:
            get_argument(f->esp, argv, 2);
            // argv[0]: 파일 이름 포인터, argv[1]: 사이즈
            
            // 파일 이름 포인터가 유효한지 검사
            check_address((void *)argv[0]);
            
            // 파일 이름이 NULL이면 종료
            if ((const char *)argv[0] == NULL) {
                exit(-1);
            }

            // 파일 생성 시도 및 결과 반환
            f->eax = filesys_create((const char *)argv[0], (unsigned)argv[1]);
            break;
            
        /* --- [수정됨] REMOVE 구현 --- */
        case SYS_REMOVE:
            get_argument(f->esp, argv, 1);
            // argv[0]: 파일 이름 포인터

            // 파일 이름 포인터가 유효한지 검사
            check_address((void *)argv[0]);

            if ((const char *)argv[0] == NULL) {
                exit(-1);
            }

            // 파일 삭제 시도 및 결과 반환
            f->eax = filesys_remove((const char *)argv[0]);
            break;
        
        case SYS_OPEN:
            get_argument(f->esp, argv, 1);
            f->eax = open((const char *)argv[0]);
            break;

        case SYS_FILESIZE:
            get_argument(f->esp, argv, 1);
            f->eax = filesize(argv[0]);
            break;

        case SYS_READ:
            get_argument(f->esp, argv, 3);
            f->eax = read(argv[0], (void *)argv[1], (unsigned)argv[2]);
            break;

        case SYS_WRITE:
            get_argument(f->esp, argv, 3);
            // argv[0]: fd, argv[1]: buffer 주소, argv[2]: size
            
            check_address((void *)argv[1]); // 버퍼 주소 체크

            // fd == 1 (STDOUT) 일 때만 화면에 출력
            if (argv[0] == 1) {
                // putbuf: 화면에 문자열을 뿌리는 핀토스 함수
                putbuf((const char *)argv[1], (unsigned)argv[2]); 
                f->eax = argv[2]; // 출력한 바이트 수 반환
            } 
            else {
                // 파일 쓰기는 아직 구현 안 함 (0 반환)
                f->eax = 0; 
            }
            break;

        case SYS_SEEK:
            get_argument(f->esp, argv, 2);
            seek(argv[0], (unsigned)argv[1]);
            break;

        case SYS_TELL:
            get_argument(f->esp, argv, 1);
            f->eax = tell(argv[0]);
            break;

        case SYS_CLOSE:
            get_argument(f->esp, argv, 1);
            close(argv[0]);
            break;

        default:
            exit(-1);
    }
}