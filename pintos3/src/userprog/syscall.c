#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);
void get_argument(void *esp , int *arg, int count);
struct vm_entry *check_address(void *addr, void *esp);
void check_valid_string (const void *str, void *esp);
void check_valid_buffer (void *buffer, unsigned size, void *esp, bool to_write);

void halt(void);
void exit(int status);
tid_t exec(const char *cmd_line);
int wait (tid_t tid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* lock 초기화 */
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[3];
  /* 유저 스택포인터 가져옴 */
  uint32_t *sp = f -> esp;
  /* 유저 스택포인터가 올바른 주소인지 확인 */
  check_address(sp, sp);

  /* 시스템 콜 넘버를 저장 */
  int syscall_n = *sp;

  /* 해당 시스템 콜 넘버에 해당하는 시스템 콜 호출 */ 
  switch(syscall_n)
  {
	case SYS_HALT : 
	halt();
	break;

	case SYS_EXIT :

	/* 유저 스택에 존재하는 인자값을 arg에 저장 */
	get_argument(sp , arg , 1);
	exit(arg[0]);
	/* 시스템 콜의 리턴 값이 있을 경우 리턴 값을 eax 레지스터에 저장 */
	f -> eax = arg[0];
	break;

	case SYS_EXEC :
	get_argument(sp , arg , 1);	
	/* 인자의 주소가 올바른지 확인 */
	check_valid_string ((void *) arg[0], sp);
	f -> eax = exec((const char *)arg[0]);
	break;

	case SYS_WAIT :
	get_argument(sp , arg , 1);
	f -> eax = wait(arg[0]);
	break;

	case SYS_CREATE :
	get_argument(sp , arg , 2);
	check_valid_string ((void *) arg[0], sp);
	f -> eax = create((const char *)arg[0] , (unsigned)arg[1]);	
	break;

	case SYS_REMOVE :
	get_argument(sp , arg , 1);
	check_valid_string ((void *) arg[0], sp);
	f -> eax = remove((const char *)arg[0]);
	break;

	case SYS_OPEN :
	get_argument(sp, arg , 1);
	check_valid_string ((void *) arg[0], sp);
	f -> eax = open((const char *)arg[0]);
	break;
	
	case SYS_FILESIZE :
	get_argument(sp, arg , 1);
	f -> eax = filesize(arg[0]);
	break;

	case SYS_READ :
	get_argument(sp, arg , 3);
	check_valid_buffer ((void *)arg[1], arg[2], sp, true);
	f -> eax = read(arg[0] , (void *)arg[1] , (unsigned)arg[2]);
	break;

	case SYS_WRITE :
	get_argument(sp, arg , 3);
	check_valid_buffer ((void *)arg[1], arg[2], sp, false);
	f -> eax = write(arg[0] , (const void *)arg[1] , (unsigned)arg[2]);
	break;

	case SYS_SEEK :
	get_argument(sp , arg , 2);
	seek(arg[0] , (unsigned) arg[1]);
	break;

	case SYS_TELL :
	get_argument(sp , arg , 1);
	f -> eax = tell(arg[0]);
	break;

	case SYS_CLOSE :
	get_argument(sp , arg , 1);
	close(arg[0]);	
	break;

	default :
	printf("not\n");
  	printf ("system call!\n");
	thread_exit ();
	}	

}

void get_argument(void *esp, int *arg , int count)
{
	int i;
	int *ptr;
	
        /* 스택 포인터에서 주소 4씩 증가하여 인자값을 arg에 저장 */ 
	for(i = 0 ; i < count ; i++)
	{
		ptr = (int *)esp + i + 1;
		check_address(ptr, ptr);
		arg[i] = *ptr;
	}
}

struct vm_entry*
check_address(void *addr, void *esp UNUSED)
{
	/* 유저 메모리 영역이 아니면 프로그램 종료 */
	if(addr < (void *)0x08048000 || addr >= (void *)0xc0000000)
	{	
		exit(-1);
	}
	return find_vme(addr);
}

/* From buffer ~ buffer+size */
/* There must being a correspond vm_entries */
/* And in case of READ system call(to_write == true) */
/* writable member of vm_entry sturcture must be true */
void
check_valid_buffer (void *buffer, unsigned size, void *esp, bool to_write)
{
	struct vm_entry *vme;
	unsigned i;

	for (i=0; i<size; i++){
		vme = check_address(buffer+i, esp);
		if(vme && to_write){
			if(!vme->writable) exit(-1);
		}
	}
}

/* Check existence of vm_entry about str */
void
check_valid_string (const void *str, void *esp)
{
	/* Until meet NULL */
	while(*(char *)str != '\0'){
		check_address((void *)str++, esp);
	}
}

void halt(void)
{
	/* pintos 종료 */
	printf("system halt\n");	
	shutdown_power_off();
}

void exit(int status)
{
	/* 현재 프로세스의 디스크립터를 가져옴 */
	struct thread *cur = thread_current();   
	/* 프로세스의 종료 status를 저장 */	
	cur -> exit_status = status;
	printf("%s: exit(%d)\n" , cur -> name , status);
	/* 프로세스(스레드) 종료 */
	thread_exit();

}

tid_t exec(const char *cmd_line)
{
	/* cmd 라인에 해당하는 프로그램 실행 */
	tid_t tid = process_execute(cmd_line);
	/* 실행한 프로그램의 프로세스 디스크립터를 가져옴 */
	struct thread *cp = get_child_process(tid);
	if(!cp)
	{
		return -1;
	}
	/* 현재 프로그램이 로드가 되지 않았으면 로드가 될때까지 대기 */
	if(cp -> load == NO_LOAD)
	{
		sema_down(&cp -> sema_load);
	}
	/* 프로그램 로드가 실패하였으면 -1 리턴 */
	if(cp -> load == FAIL_LOAD)
	{
		return -1;
	}
	
	/* 실행된 프로그램의 tid 반환 */
	return tid;	
}

int wait(tid_t tid)
{
	return process_wait(tid);
}

bool create(const char *file , unsigned initial_size)
{
	bool success = filesys_create(file , initial_size);
	return success;
}

bool remove(const char *file)
{
	bool success = filesys_remove(file);
	return success;
}


int open(const char *file)
{
	/* 파일이름에 해당하는 파일을 열고 파일 객체를 저장 */
	struct file *f = filesys_open(file);
	if(!f)
	{
		return -1;
	}
	/* 파일 객체에 대한 파일 디스크립터를 할당 */
	int fd = process_add_file(f);
	return fd;
}

int filesize (int fd)
{
 	/* 파일 디스크립터의 대한 파일 객체를 가져옴 */
	struct file *f = process_get_file(fd);
	if(!f)
	{
		return -1;
	}
	/* 해당 파일 객체에 대한 파일 크기를 알려줌 */
	int size = file_length(f);
	return size;
}

int read (int fd, void *buffer, unsigned size)
{
	unsigned i;

	/* fd 가 1일 경우 -1 리턴 */
	if (fd == STDOUT_FILENO)
		return -1;

	/* fd 가 0일 경우 키보드에 데이터를 읽음 */
	if (fd == STDIN_FILENO)
	{	
		uint8_t *local_buffer = (uint8_t *) buffer;
		/* input_getc() 를 이용하여 키보드의 데이터를 가져와 buffer에 저장 */
		for(i = 0; i < size ; i++)
		{
			local_buffer[i] = input_getc();
		}
	return size;
	}

	/* read의 동시 접근을 막기 위해 락 사용 */
	lock_acquire(&filesys_lock);
	/* 파일 디스크립터에 해당하는 파일객체를 가져옴 */
	struct file *f = process_get_file(fd);

	if(!f)
	{
		lock_release(&filesys_lock);
		return -1;
	}

	/* 파일 객체에 해당하는 파일의 데이터를 size만큼 읽는다. */
	int bytes = file_read(f, buffer, size);
	/* 락 해제 */
	lock_release(&filesys_lock);
	return bytes;
}

int write(int fd, const void *buffer, unsigned size)
{
	/* fd 값이 0일 경우 -1 리턴 */
	if(fd == STDIN_FILENO)
		return -1;

	/* fd가 1일 경우 buffer의 값을 화면에 출력 */
	if(fd == STDOUT_FILENO)
	{
		putbuf((const char *)buffer , size);
		return size;	
	}

	/* 동시 접근을 막기위한 락 사용 */
	lock_acquire(&filesys_lock);
	/* 파일 디스크립터에 해당하는 파일 객체를 가져옴 */
	struct file *f = process_get_file(fd);
	if(!f)
	{
		lock_release(&filesys_lock);
		return -1;
	}

	/* 파일 객체에 해당하는 파일의 데이터를 size만큼 기록 */
	int bytes = file_write(f, buffer, size);
	lock_release(&filesys_lock);
	return bytes;
}

void seek (int fd, unsigned position)
{
	/* 파일 디스크립터에 해당하는 파일 객체를 가져옴 */
	struct file *f = process_get_file(fd);
	if(!f)
	{
		return;
	}
	/* 파일의 위치를 position만큼 이동 */
	file_seek(f, position);
}

unsigned tell (int fd)
{
	/* 파일 디스크립터에 해당하는 파일 객체를 가져옴 */
	struct file *f = process_get_file(fd);
	if(!f)
	{
		return -1;
	}
	/* 파일의 위치를 알려줌 */ 
	off_t offset = file_tell(f);
	return offset;
}

void close (int fd)
{
	/* fd에 해당하는 파일을 닫음 */
	process_close_file(fd);
}


