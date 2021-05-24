#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include <sched.h>

#define ARRAYELTS(x) ((sizeof(x)/sizeof((x)[0])))
static int fd;
static pid_t child;
static int pfd[4];
static char *command;
static unsigned long max_time;

static void *thread_routine(void *offset_v)
{
  unsigned long off = (unsigned long)offset_v;
  volatile unsigned long *page = mmap(NULL, 16384, PROT_READ|PROT_WRITE,
				      MAP_SHARED, fd, off);

  if (page == MAP_FAILED)
    return NULL;

  /* just our marker constant. */
  while (page[0] == 0x5a6b448a98b350b6) {
    /* Make sure that the page counter is still being incremented
     * (i.e. there's live code on the other side). */
    unsigned long count = page[1];
    struct timeval starttime, curtime;
    gettimeofday(&starttime, NULL);
    while (page[1] == count) {
      gettimeofday(&curtime, NULL);
      if (1000000L * (curtime.tv_sec - starttime.tv_sec) + (curtime.tv_usec - starttime.tv_usec) > 100000)
	goto noluck;
    }

    if (page[5] - 60 > max_time)
      max_time = page[5] - 60;
    switch(page[4]) {
    case 'R': {
      /* read half a page */
      unsigned long addr = page[3];
      volatile void *mapped = mmap(NULL, 16384, PROT_READ|PROT_WRITE,
				   MAP_SHARED, fd, addr & ~16383L);
      memset((void *)(page + 1024), 0, 8192);
      memcpy((void *)(page + 1024), (void *)(mapped + (addr & 16383)), 8192);
      break;
    }
    case 'W': {
      /* write half a page */
      unsigned long addr = page[3];
      volatile void *mapped = mmap(NULL, 8192, PROT_READ|PROT_WRITE,
				   MAP_SHARED, fd, addr);
      memset((void *)(page + 1024), 0, 8192);
      memcpy((void *)(mapped), (void *)(page + 1024), 8192);
      break;
    }
    case 'C': {
      /* execute an immediate command, returning up to 8192 bytes of data */
      unsigned long addr = page[3];
      FILE *stream = popen((char *)(page + 1024), "r");
      page[3] = fread((void *)(page + 1024), 1, 8192, stream);
      pclose(stream);
      break;
    }
    case '|': {
      /* execute a command with stdio */
      command = strdup((char *)(page + 1024));
      pipe(pfd);
      pipe(pfd + 2);
      child = fork();
      if (child == 0) {
	close(pfd[1]);
	close(pfd[2]);
	dup2(pfd[0], 0);
	dup2(pfd[3], 1);
	dup2(pfd[3], 2);
	system(command);
	exit(0);
      } else {
	close(pfd[0]);
	close(pfd[3]);
      }
      break;
    }
    case '>': {
      /* send to stdio command */
      page[3] = write(pfd[1], (void *)(page + 1024), page[3]);
      break;
    }
    case '<': {
      /* receive from stdio command */
      fd_set readfds;
      FD_ZERO(&readfds);
      FD_SET(pfd[2], &readfds);
      struct timeval timeout = { 0, };
      if (select(pfd[2] + 1, &readfds, NULL, NULL, &timeout)) {
	page[3] = read(pfd[2], (void *)(page + 1024), 8192);
      } else {
	page[3] = read(pfd[2], (void *)(page + 1024), 8192);
      }
      break;
    }
    default:
      break;
    }
    asm volatile("isb");
    asm volatile("dmb sy");
    asm volatile("dsb sy");
    asm volatile("isb");
    page[4] = 0;
  }
 noluck:
  munmap((void *)page, 16384);
  return NULL;
}

static struct {
  pthread_t thread;
  unsigned long off;
} threads[16];

int main(void)
{
  fd = open("/dev/mem", O_RDWR);
  while (true) {
    /* This is important, or we'll hog the memory bus and MacOS won't boot. */
    sleep(5);
    for (unsigned long off = 0x800000000; off < 0xa00000000; off += 16384)
      {
	if (!(off & 0xfffffff))
	  sched_yield();
	volatile unsigned long *page = mmap(NULL, 16384, PROT_READ|PROT_WRITE,
					    MAP_SHARED, fd, off);
	if (page == MAP_FAILED)
	  continue;

	if (page[0] == 0x5a6b448a98b350b6 && page[5] >= max_time) {
	  size_t i;
	  for (i = 0; i < ARRAYELTS(threads); i++) {
	    if (threads[i].off == 0) {
	    } else if (pthread_tryjoin_np(threads[i].thread, NULL) == 0) {
	      threads[i].off = 0;
	    } else if (threads[i].off == off) {
	      goto nextoff;
	    }
	  }
	  for (i = 0; i < ARRAYELTS(threads); i++) {
	    if (threads[i].off == 0) {
	      if (pthread_create(&threads[i].thread, NULL, thread_routine,
				 (void *)off) != 0) {
		thread_routine((void *)off);
	      } else {
		threads[i].off = off;
	      }
	      goto nextoff;
	    }
	  }
	  thread_routine((void *)off);
	}
      nextoff:
	munmap((void *)page, 16384);
      }
  }

  exit(1);
}
