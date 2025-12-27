#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* 자식 프로세스 찾기 함수 정의 */
struct thread *get_child_process(int pid);
void remove_child_process(struct thread *child);

/* Starts a new thread running a user program loaded from
   FILENAME. */
tid_t
process_execute (const char *file_name) 
{
    char *command_line;
    char *name;
    char *remain;
    tid_t tid;

    /* 1. command_line 메모리 할당 및 복사 */
    command_line = palloc_get_page (0);
    if (command_line == NULL)
        return TID_ERROR;
    strlcpy (command_line, file_name, PGSIZE);

    /* 2. name 메모리 할당 및 복사 */
    name = palloc_get_page(0);
    if (name == NULL) {
        palloc_free_page(command_line);
        return TID_ERROR;
    }
    strlcpy (name, file_name, PGSIZE);

    /* 3. Name Parsing */
    char *program_name = strtok_r(name, " ", &remain);

    /* 4. Thread 생성 */
    tid = thread_create (program_name, PRI_DEFAULT, start_process, command_line);

    /* 5. 메모리 해제 */
    palloc_free_page(name); 

    if (tid == TID_ERROR) {
        palloc_free_page (command_line);
        return TID_ERROR;
    }

    /* 자식 스레드 찾기 및 로드 대기 */
    struct thread *child = get_child_process(tid);
    if (child != NULL) {
        sema_down(&child->load_sema);

        if (!child->load_success) {
            return TID_ERROR; 
        }
    }
    return tid;
}
/* A thread function that loads a user process and starts it running. */
static void
start_process (void *file_name_)
{
    char *command_line = file_name_;
    struct intr_frame if_;
    bool success;
    
    char *remain;
    char **argv;
    int argc = 0;
    
    argv = palloc_get_page(0);
    if (argv == NULL)
    {
        palloc_free_page(command_line);
        exit(-1);
    }

    /* 1. Argument Parsing */
    for (argv[argc] = strtok_r (command_line, " ", &remain);
         argv[argc] != NULL;
         argv[argc] = strtok_r (NULL, " ", &remain))
    {
        argc++;
    }

    /* 2. Interrupt Frame 초기화 */
    memset (&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    /* 3. Load 실행 */
    success = load (argv[0], &if_.eip, &if_.esp);
    
    /* 4. 부모 프로세스 동기화 */
    thread_current()->load_success = success;
    sema_up(&thread_current()->load_sema);

    /* 5. Load 성공 시 Stack 구성 */
    if (success)
    {
        int arg_len = 0;
        int total_len = 0;
        int start = argc - 1;

        /* [A] 문자열을 스택에 저장 (역순) */
        /* save_to_stack 헬퍼 제거하고 직접 제어하여 버그 방지 */
        for(int i = start; i >= 0; i--)
        {
            arg_len = strlen(argv[i]) + 1;
            if_.esp -= arg_len;           // 스택 공간 확보
            memcpy(if_.esp, argv[i], arg_len); // 문자열 복사
            argv[i] = if_.esp;            // 스택 상의 주소 저장
            total_len += arg_len;
        }

        /* [B] Word Align (4바이트 정렬) */
        /* 여기가 문제였습니다! memset으로 정확히 필요한 만큼만 0을 채웁니다. */
        int remainder = total_len % 4;
        if (remainder != 0)
        {
            int padding = 4 - remainder;
            if_.esp -= padding;
            memset(if_.esp, 0, padding); // 0으로 채움
        }

        /* [C] NULL Pointer Sentinel (argv[argc] = NULL) */
        if_.esp -= 4;
        *(uint32_t *)if_.esp = 0;

        /* [D] argv 포인터들의 주소 저장 (char *argv[]) */
        for(int i = start; i >= 0; i--)
        {
            if_.esp -= 4;
            *(uint32_t *)if_.esp = (uint32_t)argv[i];
        }

        /* [E] argv 배열의 시작 주소 (char **argv) */
        uint32_t argv_start = (uint32_t)if_.esp;
        if_.esp -= 4;
        *(uint32_t *)if_.esp = argv_start;

        /* [F] argc 저장 (int argc) */
        if_.esp -= 4;
        *(int *)if_.esp = argc;

        /* [G] Fake Return Address (void *ret) */
        if_.esp -= 4;
        *(void **)if_.esp = NULL;

        /* 6. 메모리 해제 */
        palloc_free_page(argv);
        palloc_free_page(command_line);

        /* Context Switch */
        asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
        NOT_REACHED ();
    }
    
    /* 7. Load 실패 시 */
    else
    {
        palloc_free_page(argv);
        palloc_free_page(command_line);
        exit(-1);
    }
}

struct thread *get_child_process(int pid)
{
 struct list_elem *e;
 struct thread *cur = thread_current();
 struct thread *child;

 for (e = list_begin(&cur->children);
      e != list_end(&cur->children);
      e = list_next(e))
 {
    child = list_entry(e, struct thread, child_elem);
    if (child->tid == pid)
        return child;
 }
 return NULL;
}

void remove_child_process (struct thread *child)
{
 if (child != NULL)
 {
    list_remove(&child->child_elem);
 }
}

struct file *process_get_file (int fd)
{
 struct thread *cur = thread_current();
 if ((2 <= fd) && (fd < cur->fd_max))
 {
    return cur->fd_table[fd];
 }
 else
    exit(-1);
}

int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *child = get_child_process(child_tid);

  if (child == NULL) {
      return -1;
  }

  sema_down(&child->exit_sema);

  int exit_status = child->exit_status;
  remove_child_process(child);
  sema_up(&child->free_sema); // 자식 소멸 허용

  return exit_status;
}

int process_add_file (struct file *f)
{
 struct thread *cur = thread_current();
 int fd = cur->fd_max;
 cur->fd_table[fd] = f;
 cur->fd_max++;
 return fd;
}

void process_close_file (int fd)
{
 struct thread* cur = thread_current();
 struct file *file = process_get_file(fd);

 if (file == NULL) return;
 
 if ((2 <= fd) && (fd < cur->fd_max))
 {
    file_close(file);
    cur->fd_table[fd] = NULL;
    for (int i = fd; i < cur->fd_max-1; i++)
        cur->fd_table[i] = cur->fd_table[i+1];
    cur->fd_max--;
 }
}

void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* 1. 종료 메시지 출력 (필수 요구사항) */
  printf ("%s: exit(%d)\n", cur->name, cur->exit_status);

  /* 2. [추가] 열린 파일 닫기 및 FD 테이블 메모리 해제 */
  if (cur->fd_table != NULL) 
    {
      /* 0, 1은 예약, 2부터 시작. 
         안전을 위해 128(또는 fd_max)까지 돌며 NULL이 아닌 것만 닫음 */
      for (int i = 2; i < cur->fd_max; i++) 
        {
          if (cur->fd_table[i] != NULL) 
            {
              file_close (cur->fd_table[i]);
              cur->fd_table[i] = NULL;
            }
        }
      palloc_free_page (cur->fd_table); // 페이지 할당 해제
      cur->fd_table = NULL; // 댕글링 포인터 방지
    }

  /* 3. 실행 중인 파일 닫기 (write deny 해제) */
  if (cur->current_file != NULL) 
    {
      file_close (cur->current_file);
      cur->current_file = NULL;
    }

  /* 4. 메모리 정리 (페이지 디렉토리 파괴) */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* 5. 부모 프로세스와의 동기화 */
  /* 주의: 페이지 디렉토리 유무와 상관없이 항상 수행해야 함 */
  sema_up (&cur->exit_sema);   // 부모에게 "나 죽는다" 알림
  sema_down (&cur->free_sema); // 부모가 exit_status를 가져갈 때까지 대기
}

void
process_activate (void)
{
  struct thread *t = thread_current ();
  pagedir_activate (t->pagedir);
  tss_update ();
}

/* ELF 관련 코드 (수정 없음) */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;
#define PE32Wx PRIx32 
#define PE32Ax PRIx32 
#define PE32Ox PRIx32 
#define PE32Hx PRIx16 

struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

#define PT_NULL    0  
#define PT_LOAD    1  
#define PT_DYNAMIC 2  
#define PT_INTERP  3  
#define PT_NOTE    4  
#define PT_SHLIB   5  
#define PT_PHDR    6  
#define PT_STACK   0x6474e551 

#define PF_X 1 
#define PF_W 2 
#define PF_R 4 

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  if (!setup_stack (esp))
    goto done;

  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

 done:
  file_close (file);
  return success;
}

static bool install_page (void *upage, void *kpage, bool writable);

static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  if (phdr->p_memsz == 0)
    return false;
  
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  if (phdr->p_vaddr < PGSIZE)
    return false;

  return true;
}

static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}