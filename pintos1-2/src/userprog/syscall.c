#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"


static void syscall_handler (struct intr_frame *);

// #0 argument
void halt (void);

// #1 argument
void exit (int status);
bool remove (const char *file);
tid_t exec (const char *cmd_line);
int wait (tid_t tid);
int open (const char *file);	//fd
int filesize (int fd);	//fd
unsigned tell (int fd);	//fd
void close (int fd);	//fd

// #2 argument
bool create (const char *file, unsigned initial_size);
void seek (int fd, unsigned position);	//fd

// #3 argumnet
int read (int fd, void *buffer, unsigned size);		//fd
int write (int fd, void *buffer, unsigned size);	//fd

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&filesys_lock);
}


/* Get system call number from the interrupt frame and 
	 implement the system call func which is correspronded to the number */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int syscall_number;
	uint32_t *esp = f->esp;
	int arg[3];

	check_address( (void *)esp, (void *)esp );
	syscall_number = *(int *)esp;


	// 1. Get argument from the USER STACK
	// 2. Check whether the address referenced by system call argument is in USER SPACE
	// 3. Return value of system call func will be saved at "eax" in intr_frame
	switch (syscall_number){
		
		// no argument
		case SYS_HALT:
			halt();
			break;

		// #1 argument
		case SYS_EXIT:
			get_argument(esp, arg, 1);
			exit(arg[0]);
			break;
		case SYS_REMOVE:
			get_argument(esp, arg, 1);
			check_valid_string((void *) arg[0], esp);
			f->eax = remove((const char *) arg[0]);
			break;
		case SYS_EXEC:
			get_argument(esp, arg, 1);
			check_valid_string((void *) arg[0], esp);
			f->eax = exec((const char *) arg[0]);
			break;
		case SYS_WAIT:
			get_argument(esp, arg, 1);
			f->eax = wait((tid_t) arg[0]);
			break;
		case SYS_OPEN:
			get_argument(esp, arg, 1);
			check_valid_string((void *) arg[0], esp);
			f->eax = open( (const char *) arg[0]);
			break;
		case SYS_FILESIZE:
			get_argument(esp, arg, 1);
			f->eax = filesize((int) arg[0]);
			break;
		case SYS_TELL:
			get_argument(esp, arg, 1);
			f->eax = tell((int) arg[0]);
			break;
		case SYS_CLOSE:
			get_argument(esp, arg, 1);
			close((int) arg[0]);
			break;

		// #2 argument
		case SYS_CREATE:
			get_argument(esp, arg, 2);
			check_valid_string((void *) arg[0], esp);
			f->eax = create((const char *) arg[0], (unsigned) arg[1]);
			break;
		case SYS_SEEK:
			get_argument(esp, arg, 2);
			seek((int) arg[0], (unsigned) arg[1] );
			break;

		// #3 argument
		case SYS_READ:
			get_argument(esp, arg, 3);
			check_valid_buffer((void *) arg[1], arg[2], esp, true);
			f->eax = read((int) arg[0], (void *) arg[1], (unsigned) arg[2]);
			break;
		case SYS_WRITE:
			get_argument(esp, arg, 3);
			check_valid_buffer((void *) arg[1], arg[2], esp, false);
			f->eax = write((int) arg[0], (void *) arg[1], (unsigned) arg[2]);
			break;		
	}

}

/* USER SPACE : 0x8048000~0xC0000000 */
struct vm_entry*
check_address (void *addr, void *esp /*Unused*/)
{
	if(!is_user_vaddr(addr) || ( addr <= (void *)0x8048000)){
		exit(-1);
	}
	return find_vme(addr);	
}

/* Check if buffer is valid or not */
void 
check_valid_buffer (void *buffer, unsigned size, void *esp, bool to_write)
{
	struct vm_entry *vme;
	unsigned i;

	for(i=0; i<size; i++){
		vme = check_address(buffer+i,esp);
		if(vme && to_write){
			if(vme->writable == false) exit(-1);
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

void
get_argument (void *esp, int *arg, int count)
{
	int n;
	esp+=4;

	// Need to check if every address we use is in USER SPACE
	for(n=0; n<count; n++){
		check_address(esp,esp);
		arg[n] = *(int *)esp;
		esp+=4;
	}
}

/* Power Off pintOS */
void
halt (void)
{
	shutdown_power_off();
}

/* Exit the current process */
void exit (int status)
{
	struct thread *t = thread_current();
	t->ret_status = status;
	printf("%s: exit(%d)\n",t->name,status);
	thread_exit();
}

/* Make file, success:true/fail:false */
bool 
create (const char *file, unsigned initial_size)
{
	return filesys_create(file, initial_size);
}

/* Remove file, success:true/fail:false */
bool
remove (const char *file)
{
	return filesys_remove(file);
}

/* Create child process */
tid_t
exec (const char *cmd_line)
{
	tid_t tid;
	struct thread *child;

	// Make new process executing "cmd_line"
	// which is child process of current process
	tid = process_execute(cmd_line);

	child = get_child_process (tid);
	if(child == NULL) return -1;

	// Wait for child to be loaded
	sema_down(&child->sema_load);

	if(child->load_flag == false)	return -1;
	
	return tid;
}

/* Wait until child process's DYING */
int
wait (tid_t tid)
{
	return process_wait(tid);
}

/* Open File */
int
open (const char *file)
{
	struct file *f;

	// To prevent accessing to file while it is opening
	lock_acquire(&filesys_lock);

	f = filesys_open(file);
	if(f == NULL){
		lock_release(&filesys_lock);
		return -1;
	}

	lock_release(&filesys_lock);

	return process_add_file(f);
}

/* file size */
int
filesize (int fd)
{
	struct file *f = process_get_file(fd);
	if(f == NULL) return -1;

	return file_length(f);
}

/* Return offset(location) of open file */
unsigned
tell (int fd)
{
	struct file *f = process_get_file(fd);
	return file_tell(f);
}

/* Close file and remove File Descriptor */
void
close (int fd)
{
	process_close_file(fd);	
}

/* Relocate file offset */
void
seek (int fd, unsigned position)
{
	struct file *f = process_get_file(fd);
	file_seek(f, position);
}


/* Read file; Return read size of buffer */
int
read (int fd, void *buffer, unsigned size)
{
	int i = 0;
	int ret;
	struct file *f = process_get_file(fd);
	
	// To avoid simultaneous access
	lock_acquire(&filesys_lock);

	// Error
	if(fd<0) ret = -1;

	// Stdin
	else if(fd == 0){
		for(i=0; i<(int)size; i++){
			*(uint8_t *)(buffer+i) = input_getc();
		}
		ret = size;
	}
	
	// Error (stdout)
	else if(fd == 1) ret = -1;

	// Read file
	else{
		if(f == NULL) ret = -1;
		ret = file_read (f, buffer, size);
	}

	lock_release(&filesys_lock);
	return ret;
}

/* Write to file; Return written size of buffer */
int
write (int fd, void *buffer, unsigned size)
{
	int ret;
	struct file *f = process_get_file(fd);

	// To avoid simultaneous access
	lock_acquire(&filesys_lock);

	// Error
	if(fd<0 || fd>128) ret = -1;

	// Error (stdin)
	else if(fd==0) ret = -1;

	// Stdout; MAX_WRITE_SIZE==128
	else if(fd==1){
		if(size>128){
			putbuf((const char *)buffer,128);
			ret = 128;
		}
		else{
			putbuf((const char *)buffer,size);
			ret = size;
		}
	}

	// Write to file
	else{
		if(f == NULL) ret = -1;
		ret = file_write(f,buffer,size);
	}

	lock_release(&filesys_lock);
	return ret;
}


