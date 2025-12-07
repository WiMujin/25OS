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

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
    char *command_line;
    char *name;
    char *remain;
    tid_t tid;

    /* 1. command_line 메모리 할당 및 복사 */
    // start_process에 넘겨줄 전체 명령행 문자열 저장
    command_line = palloc_get_page (0);
    if (command_line == NULL)
        return TID_ERROR;
    strlcpy (command_line, file_name, PGSIZE);

    /* 2. name 메모리 할당 및 복사 */
    // 스레드의 이름(프로그램명)을 파싱하기 위한 임시 공간
    name = palloc_get_page(0);
    if (name == NULL) {
        palloc_free_page(command_line); // name 할당 실패 시 command_line도 해제 필요
        return TID_ERROR;
    }
    strlcpy (name, file_name, PGSIZE);

    /* 3. Name Parsing (핵심 변경 사항) */
    // 공백을 기준으로 첫 번째 토큰(프로그램 이름)만 추출하여 name에 저장 
    // strtok_r은 원본 문자열을 수정하므로 복사본(name)을 사용합니다.
    char *program_name = strtok_r(name, " ", &remain);

    /* 4. Thread 생성 */
    // 스레드 이름: 파싱된 프로그램 이름 (program_name)
    // start_process 인자: 전체 명령행 문자열 (command_line)
    tid = thread_create (program_name, PRI_DEFAULT, start_process, command_line);

    /* 5. 메모리 해제 */
    // 파싱을 위해 사용했던 임시 공간 name은 스레드 생성 후 필요 없으므로 해제 [cite: 103]
    // 주의: palloc으로 할당한 페이지의 시작 주소를 해제해야 합니다. 
    // (위에서 name 변수를 strtok_r 리턴값으로 덮어쓰지 않도록 주의하거나, 원본 포인터를 해제해야 함)
    palloc_free_page(name); 

    if (tid == TID_ERROR)
        palloc_free_page (command_line);

    return tid;
}

/* 인자들을 스택에 저장하는 헬퍼 함수 */
void
save_to_stack (void **esp, int length, char *text, int num, int method)
{
  *esp -= length;  // 스택 공간 확보 (아래로 성장)
  
  if (method) // 문자열 저장 모드
    {
      strlcpy (*esp, text, length); 
    }
  else
    {
      **(uint32_t **)esp = num; // 해당 위치에 값 저장
    }
}
/* A thread function that loads a user process and starts it
   running. */
/* userprog/process.c */

static void
start_process (void *file_name_)
{
    char *command_line = file_name_;
    struct intr_frame if_;
    bool success;
    
    /* 보고서 Page 6 [cite: 145-148] */
    char *remain;
    char **argv;
    int argc = 0;
    
    argv = palloc_get_page(0); // [cite: 148]
    if (argv == NULL) // 예외 처리 추가
    {
        palloc_free_page(command_line);
        exit(-1);
    }

    /* 1. Argument Parsing (argc 계산) */
    /* 보고서 Page 6 [cite: 150-155] */
    // 보고서에는 따옴표 오타가 있어 " " (공백)으로 수정함
    for (argv[argc] = strtok_r (command_line, " ", &remain);
         argv[argc] != NULL;
         argv[argc] = strtok_r (NULL, " ", &remain))
    {
        argc++;
    }

    /* 2. Interrupt Frame 초기화 */
    /* 보고서 Page 7 [cite: 158-161] */
    memset (&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    /* 3. Load 실행 */
    /* 보고서 Page 7 [cite: 163] */
    success = load (argv[0], &if_.eip, &if_.esp);
    
    /* 4. 부모 프로세스 동기화 */
    /* 보고서 Page 7 [cite: 164-165] */
    thread_current()->is_load = success;
    sema_up(&thread_current()->sema_load);

    /* 5. Load 성공 시 Stack 구성 */
    /* 보고서 Page 7 [cite: 168] ~ Page 43 [cite: 1173] */
    if (success)
    {
        int arg_len = 0;
        int total_len = 0;
        int start = argc - 1;

        /* [A] 문자열을 스택에 저장 (역순) [cite: 172-177] */
        for(int i = start; i >= 0; i--)
        {
            arg_len = strlen(argv[i]) + 1;
            total_len += arg_len;
            save_to_stack(&if_.esp, arg_len, argv[i], 0, 1);
            argv[i] = if_.esp; // 스택 주소로 업데이트 [cite: 177]
        }

        /* [B] Word Align (4바이트 정렬) [cite: 180-183] */
        if (total_len % 4)
        {
            // 보고서의 의도대로 패딩 계산 로직 적용
            save_to_stack(&if_.esp, 4 - (total_len % 4), NULL, 0, 0); 
        }

        /* [C] NULL Pointer Sentinel (argv[argc]) [cite: 183] */
        save_to_stack(&if_.esp, 4, NULL, 0, 0);

        /* [D] argv 포인터들의 주소 저장 [cite: 184-185] */
        for(int i = start; i >= 0; i--)
        {
            save_to_stack(&if_.esp, 4, NULL, (uint32_t)argv[i], 0);
        }

        /* [E] argv 배열의 시작 주소 (char **) [cite: 186-187] */
        // 보고서: if_.esp -= 4; *(uint32_t **)if_.esp = if_.esp+4;
        // 위 로직과 동일하게 save_to_stack 활용
        save_to_stack(&if_.esp, 4, NULL, (uint32_t)(if_.esp + 4), 0);

        /* [F] argc 저장 [cite: 188-190] */
        save_to_stack(&if_.esp, 4, NULL, argc, 0);

        /* [G] Fake Return Address [cite: 191-193] */
        save_to_stack(&if_.esp, 4, NULL, 0, 0);

        /* 6. 메모리 해제 (성공 시) [cite: 1176-1177] */
        // Multi-oom 해결을 위한 위치
        palloc_free_page(argv);
        palloc_free_page(command_line);

        //hex_dump(if_.esp, if_.esp, PHYS_BASE - if_.esp, true); // 디버깅용 [cite: 1159]

        /* Context Switch */
        asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
        NOT_REACHED ();
    }
    
    /* 7. Load 실패 시 [cite: 1178-1183] */
    else
    {
        // Multi-oom 해결을 위해 실패 시에도 반드시 free
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

 // child list를 돌며 요청한 pid를 가진 chiild가 있는지 탐색
 for (e = list_begin(&cur->child_list);
 e != list_end(&cur->child_list);
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
 palloc_free_page(child);
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

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  return -1;
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

 if (file == NULL)
 return;
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

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
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

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
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

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
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

  /* Read program headers. */
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
          /* Ignore this segment. */
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
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
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

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
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
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
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

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
