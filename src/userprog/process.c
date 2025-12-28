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
  char *fn_copy;
  tid_t tid;

  /* 1. 실행 파일 이름의 사본 생성 (커널 스택용) */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* 2. 스레드 이름을 파싱하기 위한 임시 사본 생성 */
  /* file_name을 직접 strtok 하면 원본이 망가질 수 있어 사본 사용 */
  char *name_copy = palloc_get_page(0);
  if (name_copy == NULL) {
      palloc_free_page(fn_copy);
      return TID_ERROR;
  }
  strlcpy(name_copy, file_name, PGSIZE);

  char *save_ptr;
  char *prog_name = strtok_r(name_copy, " ", &save_ptr);

  /* 3. 스레드 생성 (prog_name: 프로그램 이름, fn_copy: 전체 인자) */
  tid = thread_create (prog_name, PRI_DEFAULT, start_process, fn_copy);
  
  /* 임시 사본 해제 */
  palloc_free_page(name_copy);

  if (tid == TID_ERROR)
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }

  /* 🌟 [동기화] 자식 프로세스가 로드될 때까지 대기 🌟 */
  struct thread *cur = thread_current();
  struct thread *child = NULL;
  struct list_elem *e;

  /* 자식 리스트 탐색 (get_child_process 로직 내장) */
  for (e = list_begin (&cur->children); e != list_end (&cur->children); e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, child_elem);
      if (t->tid == tid)
        {
          child = t;
          break;
        }
    }

  /* 자식을 찾았으면 로드 대기 */
  if (child != NULL) 
    {
      /* start_process에서 load가 끝날 때까지 여기서 대기 */
      sema_down (&child->load_sema); 
      
      /* 로드 실패했다면 -1(TID_ERROR) 반환 */
      if (!child->load_success) 
        {
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
    
    /* 메모리 할당 */
    argv = palloc_get_page(0);
    if (argv == NULL)
    {
        palloc_free_page(command_line);
        thread_current()->exit_status = -1;
        thread_exit();
    }

    /* 1. Argument Parsing */
    /* 커맨드 라인을 공백 기준으로 쪼개서 argv 배열에 저장 */
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

    /* 3. Load 실행 (실행 파일 메모리 적재) */
    success = load (argv[0], &if_.eip, &if_.esp);
    
    /* 🌟 [4. 부모 프로세스 동기화] 🌟 */
    /* 로드 결과를 기록하고, 기다리고 있는 부모(process_execute)를 깨움 */
    thread_current()->load_success = success;
    sema_up(&thread_current()->load_sema);

    /* 5. Load 성공 시 Stack 구성 (Argument Passing) */
    if (success)
    {
        int arg_len = 0;
        int total_len = 0;
        int start = argc - 1;

        /* [A] 문자열 데이터를 스택에 저장 (역순) */
        for(int i = start; i >= 0; i--)
        {
            arg_len = strlen(argv[i]) + 1; // NULL 문자 포함
            if_.esp -= arg_len;            // 스택 포인터 이동
            memcpy(if_.esp, argv[i], arg_len); // 데이터 복사
            argv[i] = if_.esp;             // 스택상의 주소를 argv에 갱신
            total_len += arg_len;
        }

        /* [B] Word Align (4바이트 정렬) */
        int remainder = total_len % 4;
        if (remainder != 0)
        {
            int padding = 4 - remainder;
            if_.esp -= padding;
            memset(if_.esp, 0, padding); // 패딩 0으로 채움
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

        /* 6. 메모리 해제 (임시 버퍼 정리) */
        palloc_free_page(argv);
        palloc_free_page(command_line);

        /* Context Switch (사용자 모드로 전환) */
        asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
        NOT_REACHED ();
    }
    
    /* 7. Load 실패 시 */
    else
    {
        palloc_free_page(argv);
        palloc_free_page(command_line);
        
        /* 로드 실패 상태로 종료 */
        thread_current()->exit_status = -1;
        thread_exit();
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
  struct thread *cur = thread_current ();
  struct thread *child = NULL;
  struct list_elem *e;

  /* 1. 자식 리스트를 검색하여 child_tid에 해당하는 스레드 찾기 */
  for (e = list_begin (&cur->children); e != list_end (&cur->children); e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, child_elem);
      if (t->tid == child_tid)
        {
          child = t;
          break;
        }
    }

  /* 2. 자식이 없으면 -1 반환 (내 자식이 아니거나 이미 종료됨) */
  if (child == NULL) 
    {
      return -1;
    }

  /* 3. 자식이 종료될 때까지 대기 (wait_sema) */
  /* 자식의 process_exit에서 sema_up 할 때까지 여기서 멈춤 */
  sema_down (&child->wait_sema);

  /* 4. 자식의 종료 상태 가져오기 (자식은 현재 free_sema에서 대기 중이라 메모리 안전함) */
  int exit_status = child->exit_status;

  /* 5. 자식 리스트에서 제거 (더 이상 관리하지 않음) */
  list_remove (&child->child_elem);

  /* 6. [추가] 자식에게 "이제 죽어도 좋아" 신호 보냄  */
  /* 이 신호를 보내야 자식이 process_exit의 대기 상태를 풀고 소멸됨 */
  sema_up (&child->free_sema);

  /* 7. 종료 상태 반환 */
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

  /* 1. 현재 실행 중인 파일 닫기 (쓰기 방지 해제) */
  if (cur->running_file != NULL) 
    {
      file_close (cur->running_file);
      cur->running_file = NULL;
    }

  /* 2. 열려 있는 모든 파일 닫기 및 FD 테이블 메모리 해제 */
  if (cur->fd_table != NULL) 
    {
      for (int i = 2; i < cur->fd_max; i++) 
        {
          if (cur->fd_table[i] != NULL) 
            {
              file_close (cur->fd_table[i]);
              cur->fd_table[i] = NULL;
            }
        }
      palloc_free_page (cur->fd_table); 
      cur->fd_table = NULL; 
    }

  /* 3. 종료 메시지 출력 */
  printf ("%s: exit(%d)\n", cur->name, cur->exit_status);

  /* 4. 부모에게 "나 죽는다" 알림 (wait_sema up) */
  /* 부모가 process_wait에서 자고 있다면 여기서 깨어남 */
  sema_up (&cur->wait_sema); 

  /*  5. 자식 프로세스들 놓아주기 (고아 처리)  */
  /* 내가 죽으면 자식들이 나중에 나한테 보고할 방법이 없으므로 미리 풀어줌 */
  struct list_elem *e;
  for (e = list_begin (&cur->children); e != list_end (&cur->children); e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, child_elem);
      sema_up (&t->free_sema); // 자식아, 기다리지 말고 가라
    }

  /* 🌟 6. [추가] 부모가 내 정보를 가져갈 때까지 대기 (Page Fault 방지 핵심) 🌟 */
  /* 부모가 process_wait에서 sema_up(&child->free_sema)를 해줄 때까지 대기 */
  /* 단, 부모가 이미 죽었거나 NULL이라면 기다리지 않음 */
  if (cur->parent != NULL) 
    {
      sema_down (&cur->free_sema);
    }

  /* 7. 메모리 정리 (페이지 디렉토리 파괴) */
  /* 위에서 기다려주지 않으면, 부모가 읽기도 전에 여기서 메모리가 날아감 -> Kernel Panic */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
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

  /* 페이지 디렉토리 생성 */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* 파일 열기 */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* 🌟 [수정 1] 현재 실행 중인 파일은 쓰기 금지 설정 및 저장 🌟 */
  t->running_file = file;
  file_deny_write (file);

  /* ELF 헤더 검사 */
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

  /* 프로그램 헤더 읽기 및 세그먼트 로드 */
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

  /* 스택 설정 */
  if (!setup_stack (esp))
    goto done;

  /* 엔트리 포인트 설정 및 성공 표시 */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

 done:
  /* 🌟 [수정 2] 로드에 성공했다면 파일 닫지 않음 (쓰기 금지 유지) 🌟 */
  /* 실패했을 때만 파일을 닫음 */
  if (!success) 
    {
      file_close (file);
    }
    
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