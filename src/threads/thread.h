#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Process identifier type (Project 2 addition). */
typedef tid_t pid_t;

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */

struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    /* [Project 1-1] Alarm Clock */
    int64_t wakeup;

    /* [Project 1-2] Priority Donation 필수 변수들 */
    int original_priority;              /* 기부 받기 전 원래 우선순위 */
    struct list donations;              /* 나에게 기부한 스레드 리스트 */
    struct lock *waiting_on_lock;       /* 내가 기다리는 락 */
    struct list_elem elem_for_donation; /* donation 리스트용 elem */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;          /* Page directory. */

    /* [Project 2] Process Hierarchy (족보 관리) */
    struct thread *parent;           /* 나의 부모 스레드 */
    struct list children;            /* 나의 자식 스레드 리스트 */
    struct list_elem child_elem;     /* 자식 리스트에 매달릴 나의 연결고리 */

    /* [Project 2] Synchronization & Status (연락 및 상태) */
    int exit_status;                 /* 자식의 종료 상태 (유언) */
    struct semaphore wait_sema;      /* 자식이 죽을 때까지 부모가 기다리는 곳 */
    
    /* [추가됨] 부모가 유언(exit_status)을 가져갈 때까지 자식이 기다리는 곳 🌟 */
    struct semaphore free_sema;      

    struct semaphore load_sema;      /* 자식 생성(exec)이 끝날 때까지 부모가 기다리는 곳 */
    bool load_success;               /* 자식의 프로그램 탑재 성공 여부 */

    /* [Project 2] File Descriptors (파일 관리) */
    struct file **fd_table;          /* 파일 디스크립터 테이블 */
    int fd_max;                      /* 현재 할당된 FD 최대값 */
    
    /* [Project 2] Deny Write on Executables */
    struct file *running_file;       /* 현재 실행 중인 파일 (실행 중 쓰기 금지용) */
#endif
    /* Owned by thread.c. */
    unsigned magic;                 /* Detects stack overflow. */
    
  };
/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

/* [Project 1-1] Alarm Clock Functions */
void thread_sleep (int64_t ticks);
void thread_awake (int64_t ticks);

/* [Project 1-2] Priority Scheduling Helper Functions */
void check_preemption (void);
bool priority_less_func (const struct list_elem *a, const struct list_elem *b, void *aux);
bool donation_less_func (const struct list_elem *a, const struct list_elem *b, void *aux);
void thread_recalculate_priority (struct thread *t);
void thread_remove_donors_for_lock (struct lock *lock);

#endif /* threads/thread.h */