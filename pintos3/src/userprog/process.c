#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* 첫 번째 공백 전까지의 문자열을 저장 */
  char *parse_name , *save_ptr;
  parse_name = palloc_get_page(0);
  strlcpy(parse_name , file_name , PGSIZE);
  parse_name = strtok_r(parse_name , " " , &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  /* thread_create() 함수의 첫번째 인자 값은 스레드의 이름 */
  tid = thread_create (parse_name, PRI_DEFAULT, start_process, fn_copy);

  /* 메모리 해제 */
  palloc_free_page(parse_name);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  char *token = NULL; 
  char *save_ptr = NULL;
  char **parse;
  int count = 0;
  struct intr_frame if_;
  bool success;

  /* 문자열 파싱 */
  parse = palloc_get_page(0); 
  for(token = strtok_r(file_name," ", &save_ptr) ; token != NULL ; token = strtok_r( NULL , " " , &save_ptr))
  {	
	parse[count] = malloc(strlen(token));
	strlcpy(parse[count] , token , PGSIZE);
	count++;
  }

	/* Initialize Hash Table using vm_init() */
	vm_init(&thread_current()->vm);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* 파싱된 문자열의 첫번째 문자열은 프로그램 이름 */
  success = load (parse[0] , &if_.eip, &if_.esp);

  /* If load failed, quit. */

  /* 메모리 해제 */
  palloc_free_page (file_name);

  /* 메모리 적재 완료 시 부모 프로세스 다시 진행 */
  sema_up(&thread_current() -> sema_load);

  /* 메모리 적재 실패 시 프로세스 디스크립터에 적재 실패를 알림 */
  /* 스레드 종료 */
  if (!success)
  {
  	thread_current() -> load = FAIL_LOAD;   	
	thread_exit ();
  }
  /* 메모리 적재 성공 시 프로세스 디스크립터에 적재 성공을 알림 */
  /* 유저 스택에 인자값을 저장 */
  else
  {     
	thread_current() -> load = SUCCESS_LOAD;
  	argument_stack(parse , count , &if_.esp); 
  }

  /* 메모리 해제 */
  int i;
  for(i = 0 ; i < count ; i++)
  {
	free(parse[i]);
  }

  palloc_free_page(parse);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  /* 해당 PID의 자식 프로세스 디스크립터를 가져옴 */
  struct thread *cp = get_child_process(child_tid);
  if(!cp)
	  return -1;
  if(cp -> wait)
	  return -1;
  cp -> wait = true;
  
  /* 자식 프로세스가 종료될때 까지 대기 */
  if(!cp -> exit)
  {
	sema_down(&cp -> sema_exit);
  }
  int status = cp -> exit_status;

  /* 자식 리스트에서 제거 */
  remove_child_process(cp);
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */

  /* 프로세스 종료 시 현재 실행하고 있는 프로그램을 닫음 */
  if(cur -> run_file)
  {
	file_close(cur -> run_file);
  }
 
  /* 해당 프로세스에 열린 모든 파일을 닫음 */
  while(cur -> next_fd > 2)  
  {
	cur -> next_fd--;
	process_close_file(cur -> next_fd);
  }
 
  /* 메모리 leak 방지를 위한 메모리 해제 */
  palloc_free_page(cur -> fd);

	/* Deleting vme */
	vm_destroy(&cur->vm);

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

  lock_acquire(&filesys_lock);
  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      lock_release(&filesys_lock);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  t -> run_file = file;
  file_deny_write(file);
  lock_release(&filesys_lock);

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

			/* Make vm_entry */
			struct vm_entry *vme = malloc(sizeof(struct vm_entry));
			if(vme == NULL) return false;

			/* Set up members of vm_entry */
			vme->type = VM_BIN;
			vme->vaddr = upage;
			vme->writable = writable;
			vme->is_loaded = false;
			vme->file = file;
			vme->offset = ofs;
			vme->read_bytes = page_read_bytes;
			vme->zero_bytes = page_zero_bytes;

			/* Insert vm_entry into Hash Table */
			insert_vme(&thread_current()->vm,vme);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
	ofs += page_read_bytes;
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

  /* Make vm_entry */
	struct vm_entry *vme = malloc(sizeof(struct vm_entry));
	if(vme == NULL) return false;

	/* Set up members of vm_entry */
	vme->type = VM_ANON;
	vme->vaddr = (uint8_t*)PHYS_BASE - PGSIZE;
	vme->writable = true;
	vme->is_loaded = true;
	vme->file = NULL;

	/* Insert vm_entry into Hash Table */
	insert_vme(&thread_current()->vm,vme);

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

void argument_stack(char **parse , int count , void **esp)
{	 
	int i, j;
	char **argument_address = palloc_get_page(0);
	/* 함수 호출 규약에 따라 유저 스택에 인자 저장*/  
        /* 프로그램 이름 및 인자(문자열) 저장 */ 
	for(i = count - 1 ; i > -1 ; i--)
	{
		for(j = strlen(parse[i]) ; j > -1 ; j--)
		{
			*esp = *esp - 1;
			**(char **)esp = parse[i][j];
		}
		argument_address[i] = *esp;
	}

        /* word-align */
	*esp = *esp - 1;
	uint8_t word_align = 0;
	**(uint8_t **)esp = word_align;
        
	*esp = *esp - 4;
	**(uint32_t **)esp = 0;	

	/* 프로그램 이름 및 인자를 가리키는 주소 저장 */
	for(i = count -1 ; i > -1 ; i--)
	{
		*esp = *esp - 4;
		**(uint32_t **)esp = (uint32_t)argument_address[i];
	}

	/* argv (문자열을 가리키는 주소들의 배열을 가리킴) */ 
	*esp = *esp - 4;
	**(uint32_t **)esp = *esp + 4;

	 /* argc (문자열의 개수 저장) */
	*esp = *esp - 4;
	**(uint32_t **)esp = count;

	/* fake address(0) 저장 */ 
	*esp = *esp - 4;
	**(uint32_t **)esp = 0;
	
	palloc_free_page(argument_address);	
}

int process_add_file (struct file *f)
{
	/* 현재 프로세스의 디스크립터를 가져옴 */
	struct thread *t = thread_current();
	
        /* 파일 객체에 대한 파일 디스크립터를 할당 */
        t -> fd[t -> next_fd] = f; 
	t -> next_fd++;
	return t -> next_fd - 1;
}


struct file *process_get_file(int fd)
{
	/* 현재 프로세스의 디스크립터를 가져옴 */
	struct thread *t = thread_current();
        
        /* 파일 디스크립터 테이블에서 해당 fd값의 해당하는 파일 객체 반환 */
	if(t -> fd[fd] != NULL)
		return t -> fd[fd];
	return NULL;
}


void process_close_file(int fd)
{
	/* 현재 프로세스의 디스크립터를 가져옴 */
	struct thread *t = thread_current();

	/* fd값의 해당하는 파일 객체를 이용하여 파일을 닫는다. */
        if(t -> fd[fd] != NULL)
	{
		file_close(t -> fd[fd]);
	}	
	/* 초기화 */
	t -> fd[fd] = NULL;	
}

struct thread *get_child_process (int pid)
{
	/* 현재 프로세스의 디스크립터를 가져옴 */
	struct thread *t = thread_current();

	/* 리스트의 맨 처음을 가르킴 */
	struct list_elem *next, *e = list_begin(&t -> child_list);

	/* 자식 리스트 탐색 */
        while(e != list_end(&t -> child_list))
	{	
		/* 다음 리스트로 넘어감 */
		next = list_next(e);

		/* 해당 위치에 존재하는 프로세스 디스크립터를 가져옴 */
		struct thread *cp = list_entry(e , struct thread, child_elem);

		if(pid == cp -> tid)
		{
			return cp;
		}
		e = next;
	}
	return NULL;
}



void remove_child_process(struct thread *cp)
{
	/* 현재 프로세스의 자식리스트에서 인자 값으로 가져온 스레드 삭제 */ 		
	list_remove(&cp -> child_elem);
        /* 자식 프로세스 디스크립터 메모리 해제 */
	palloc_free_page(cp);
}

/* Page fault handler */
bool
handle_mm_fault (struct vm_entry *vme)
{
	void *kaddr = palloc_get_page(PAL_USER);
	if(!kaddr) return false;

	switch(vme->type){
		case VM_BIN:
			/* load to physical memory using load_fild() */
			if(!load_file(kaddr,vme)){
				palloc_free_page(kaddr);
				return false;
			}
		break;
		case VM_FILE:
			break;
		case VM_ANON:
			break;
		default:
			return false;
	}
	/*  Mapping Virtual page with Physical page using install_page() */
	if(!install_page(vme->vaddr, kaddr,vme->writable)){
		palloc_free_page(kaddr);
		return false;
	}
	vme->is_loaded = true;
	
	return true;
}
