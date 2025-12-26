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
#include "devices/shutdown.h" // [추가] halt()를 위해 필요
#include "devices/input.h"    // [추가] input_getc()를 위해 필요

#define STACK_END 0x8048000  

static void syscall_handler (struct intr_frame *);
void get_argument(void *esp, int *argv, int count);
struct lock lock_file;

void
syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&lock_file); 
}

/* 주소 유효성 검사 */
void check_address (void *addr)
{
    /* 주소값이 유저 영역인지, NULL이 아닌지 확인 */
    if (addr == NULL || !is_user_vaddr(addr) || addr < (void *)0x08048000)
    {
        exit(-1);
    }
    
    /* 실제 매핑된 페이지인지 확인 (pagedir_get_page가 NULL이면 매핑 안됨) */
    if (pagedir_get_page(thread_current()->pagedir, addr) == NULL)
    {
        exit(-1);
    }
}

/* 인자 가져오기 헬퍼 함수 */
void
get_argument(void *esp, int *argv, int count)
{
    int *ptr = (int *)esp;
    for(int i = 0; i < count; i++)
    {
        ptr++; // 다음 인자 위치로 이동
        check_address((void *)ptr); // 포인터가 가리키는 스택 주소가 유효한지
        argv[i] = *ptr; // 값 읽어오기
    }
}

bool create(const char *file, unsigned initial_size)
{
    check_address((void *)file);
    return filesys_create(file, initial_size);
}

bool remove (const char *file)
{
    check_address((void *)file);
    return filesys_remove(file);
}

int open (const char *file)
{
    check_address((void *)file);
    
    if (file == NULL) return -1; // 방어 코드

    lock_acquire(&lock_file);
    struct file *f = filesys_open(file);
    
    /* 실행 중인 파일은 쓰기 금지 */
    if (f != NULL && strcmp(thread_current()->name, file) == 0) {
        file_deny_write(f);
    }

    int fd = -1;
    if (f != NULL) {
        fd = process_add_file(f);
    }
    lock_release(&lock_file);

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
    
    /* 버퍼의 끝 주소도 검사 (페이지 경계 넘침 방지) */
    void *end_buffer = (char *)buffer + size - 1;
    check_address(end_buffer);

    lock_acquire(&lock_file);
    int read_byte = -1;

    if (fd == 0) // STDIN
    {
        unsigned i;
        char *buf = buffer;
        for (i = 0; i < size; i++)
        {
            char key = input_getc(); // devices/input.h 필요
            *buf++ = key;
            if (key == '\0') break;
        }
        read_byte = i;
    }
    else if (fd > 1) // 파일 읽기
    {
        struct file *f = process_get_file(fd);
        if (f != NULL) {
            read_byte = file_read(f, buffer, size);
        }
    }
    lock_release(&lock_file);
    return read_byte;
}

int write (int fd, const void *buffer, unsigned size)
{
    check_address((void *)buffer);
    
    lock_acquire(&lock_file);
    int write_byte = -1;

    if (fd == 1) // STDOUT
    {
        putbuf(buffer, size);
        write_byte = size;
    }
    else if (fd > 1) // 파일 쓰기
    {
        struct file *file = process_get_file(fd);
        if (file != NULL) {
            write_byte = file_write(file, buffer, size);
        }
    }
    lock_release(&lock_file);
    return write_byte;
}

void seek (int fd, unsigned position)
{
    struct file *file = process_get_file(fd);
    if (file != NULL)
        file_seek(file, position);
}

unsigned tell (int fd)
{
    struct file *file = process_get_file(fd);
    if (file != NULL)
        return file_tell(file);
    return -1;
}

void close (int fd)
{
    process_close_file(fd);
}

/* Exit System Call */
void exit(int status)
{
    struct thread *cur = thread_current();
    
    /* 종료 상태 저장 */
    cur->exit_status = status; 
    
    /* 출력은 process_exit()에서 처리됨 */
    
    thread_exit(); 
}

void halt(void)
{
    shutdown_power_off(); // devices/shutdown.h 필요
}

int wait (pid_t pid)
{
    return process_wait(pid);
}

pid_t exec (const char *file)
{
    check_address((void *)file);
    
    /* process_execute 내부에서 로드 대기 후 성공 시 tid 반환 */
    pid_t pid = process_execute(file);
    
    return pid;
}

/* 메인 핸들러 */
static void
syscall_handler (struct intr_frame *f) 
{
    /* 스택 포인터 유효성 검사 */
    check_address(f->esp); // 스택 포인터 자체

    /* 시스템 콜 번호 읽기 */
    int syscall_number = *(int *)f->esp;
    
    int argv[3]; 

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
            f->eax = exec((const char *)argv[0]);
            break;
            
        case SYS_WAIT:
            get_argument(f->esp, argv, 1);
            f->eax = wait((pid_t)argv[0]);
            break;

        case SYS_CREATE:
            get_argument(f->esp, argv, 2);
            f->eax = create((const char *)argv[0], (unsigned)argv[1]);
            break;
            
        case SYS_REMOVE:
            get_argument(f->esp, argv, 1);
            f->eax = remove((const char *)argv[0]);
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
            f->eax = write(argv[0], (const void *)argv[1], (unsigned)argv[2]);
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