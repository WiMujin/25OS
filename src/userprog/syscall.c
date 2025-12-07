#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "process.h"
#include "filesys/file.h"

#define STACK_END 0x8048000  // 스택의 가장 아래 유효 주소 (예시)
#define STACK_BASE 0xc0000000 // 커널 영역 시작 지점 (PHYS_BASE 근처)

static void syscall_handler (struct intr_frame *);
struct lock lock_file;

void
syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&lock_file); // <-- 이 줄을 추가하여 락을 '초기화'합니다. 
}

// check_address 함수의 정의 (프로토타입이 없을 경우)
void check_address (void *addr)
{
    // 1. NULL 포인터 검사 [cite: 478, 479]
    // 2. 스택의 유효 범위 검사 (유저 스택 영역인지) [cite: 480, 483, 484]
    // 3. 사용자 영역 주소인지 검사 [cite: 488, 491]
    // 4. 해당 주소에 페이지가 할당되어 매핑되어 있는지 검사 [cite: 493, 494]
    
    if (addr == NULL || 
        addr < (void *)STACK_END || 
        addr >= (void *)STACK_BASE ||
        !is_user_vaddr(addr) ||
        pagedir_get_page(thread_current()->pagedir, addr) == NULL)
    {
        // 유효하지 않은 주소일 경우 즉시 프로세스 종료 [cite: 476]
        exit(-1);
    }
}

bool create(const char *file, unsigned initial_size)
{
 check_address(file);
 return filesys_create(file, initial_size);
}

bool remove (const char *file)
{
 check_address(file);
 return filesys_remove(file);
}

int filesize (int fd)
{
 struct file *f = process_get_file(fd);
 if (f == NULL)
 return -1;
 return
 file_length(f);
}

int open (const char *file)
{
 check_address(file);
 if (file == NULL)
 exit(-1);

 lock_acquire(&lock_file);
 struct file *f = filesys_open(file);

 if (strcmp (thread_current()->name, file) == 0)
 file_deny_write(f);
 int fd;
 if (f != NULL)
 fd = process_add_file(f);
 else
 fd = -1;
 lock_release(&lock_file);

 return fd;
}

int read (int fd, void *buffer, unsigned size)
{
 check_address(buffer);
 lock_acquire(&lock_file);
 if (fd == 0)
 {
 char key;
 unsigned i;
 unsigned char *cast_buffer = buffer;
 for (i = 0; i < size; i++)
 {
 key = input_getc();
 *cast_buffer++ = key;
 if (key == '\0')
 break;
 }
 lock_release(&lock_file);
 return i;
 }
 else
 {
 struct file *f = process_get_file(fd);
 if (f == NULL)
 {
 lock_release(&lock_file);
 return -1;
 }
 int read_byte = file_read(f, buffer, size);
 lock_release(&lock_file);
 return read_byte;
 }
}

int write (int fd, const void *buffer, unsigned size)
{
 check_address(buffer);
 int write_byte = 0;
 lock_acquire(&lock_file);
 if (fd == 1)
 {
 putbuf(buffer, size);
 write_byte = size;
 }
 else
 {
 struct file *file = process_get_file(fd);
 if (file == NULL)
 write_byte = -1;
 else
 write_byte = file_write(file, buffer, size);
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
 else
 return -1;
}

void close (int fd)
{
 process_close_file(fd);
}

void exit(int status)
{
    printf("%s: exit(%d)\n", thread_name(), status); 
    thread_current()->exit_status = status; 
    thread_exit(); 
}

void halt(void)
{
 shutdown_power_off();
}

int wait (pid_t pid)
{
 return process_wait(pid);
}

pid_t exec (const char *file)
{
 check_address(file);
 pid_t pid = process_execute(file);
 if (pid == -1)
 return -1;
 struct thread *child = get_child_process(pid);
 sema_down(&(child->sema_load));
 if (child->is_load)
  return pid;
 else
  return -1;
}

static void
get_argument(int *esp, int *argv, int argc)
{
    int i;
    for(i = 0; i < argc; i++)
    {
        // 다음 인자의 주소를 확인 (esp+1)
        check_address(esp + 1);
        esp += 1;
        // 인자 값을 argv 배열에 저장
        argv[i] = *esp;
    }
}

/* userprog/syscall.c */
static void
syscall_handler (struct intr_frame *f) 
{
    // 1. 초기 스택 포인터 유효성 검사 (시스템 콜 번호 주소)
    check_address(f->esp);

    // 2. 시스템 콜 번호 읽기 (스택 최상단)
    int syscall_number = *(int *)f->esp;
    
    // argv는 최대 3개의 인자를 임시 저장하기 위한 배열입니다.
    // 인자는 4바이트 단위로 스택에 저장됩니다.
    int argv[3]; 

    // 3. 시스템 콜 번호에 따른 분기 및 인자 처리
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
            f->eax = exec(argv[0]);
            break;
            
        case SYS_WAIT:
            get_argument(f->esp, argv, 1);
            f->eax = wait(argv[0]);
            break;

        case SYS_CREATE:
            get_argument(f->esp, argv, 2);
            f->eax = create(argv[0], argv[1]);
            break;
            
        case SYS_REMOVE:
            get_argument(f->esp, argv, 1);
            f->eax = remove(argv[0]);
            break;
        
        case SYS_OPEN:
            get_argument(f->esp, argv, 1);
            f->eax = open(argv[0]);
            break;

        // Project 2-2에서 구현할 시스템 콜은 뼈대만 남깁니다.
        case SYS_FILESIZE:
        case SYS_READ:
        case SYS_WRITE:
        case SYS_SEEK:
        case SYS_TELL:
        case SYS_CLOSE:
            // 이 함수들은 Project 2-2에서 구현되어야 링커 에러가 해결됩니다.
            // 현재는 링커 에러 방지를 위해 임시로 함수 정의가 필요합니다.
            break;

        default:
            exit(-1);
    }
    // Note: get_argument 함수 내부에서 인자 주소 유효성을 검사해야 합니다.
}


