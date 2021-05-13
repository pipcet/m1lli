#include <sys/mman.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

int main(void)
{
  int fd = open("/dev/mem", O_RDWR);
  pid_t child;
  int pfd[4];
  char *command;
  for (unsigned long off = 0x800000000; off < 0x980000000; off += 16384)
    {
      volatile unsigned long *page = mmap(NULL, 16384, PROT_READ|PROT_WRITE,
				 MAP_SHARED, fd, off);
      if (page == MAP_FAILED)
	continue;

    again:
      /* shared random constant */
      if (page[0] != 0x5a6b448a98b350b6) {
	goto noluck;
      }

      /* Make sure that the page counter is still being incremented
       * (i.e. there's live code on the other side). */
      unsigned long count = page[1];
      struct timeval starttime, curtime;
      gettimeofday(&starttime, NULL);
      while (page[1] == count) {
	gettimeofday(&curtime, NULL);
	if (starttime.tv_sec != curtime.tv_sec)
	  goto noluck;
      }

      switch(page[4]) {
      case 'R': {
	/* read half a page */
	unsigned long addr = page[3];
	volatile void *mapped = mmap(NULL, 16384, PROT_READ|PROT_WRITE,
				     MAP_SHARED, fd, addr & ~16383L);
	memset((void *)(page + 1024), 0, 8192);
	memcpy((void *)(page + 1024), (void *)(mapped + (addr & 16383)), 8192);
	page[4] = 0;
	goto again;
      }
      case 'W': {
	/* write half a page */
	unsigned long addr = page[3];
	volatile void *mapped = mmap(NULL, 8192, PROT_READ|PROT_WRITE,
				     MAP_SHARED, fd, addr);
	memset((void *)(page + 1024), 0, 8192);
	memcpy((void *)(mapped), (void *)(page + 1024), 8192);
	page[4] = 0;
	goto again;
      }
      case 'C': {
	/* execute an immediate command, returning up to 8192 bytes of data */
	unsigned long addr = page[3];
	FILE *stream = popen((char *)(page + 1024), "r");
	page[3] = fread((void *)(page + 1024), 1, 8192, stream);
	pclose(stream);
	page[4] = 0;
	goto again;
      }
      case '|': {
	/* execute a command with stdio */
	command = strdup((char *)(page + 1024));
	child = fork();
	pipe(pfd);
	pipe(pfd + 2);
	if (child == 0) {
	  close(pfd[1]);
	  close(pfd[2]);
	  dup2(pfd[0], 0);
	  dup2(pfd[3], 1);
	  system(command);
	  exit(0);
	} else {
	  close(pfd[0]);
	  close(pfd[3]);
	}
	goto again;
      }
      case '>': {
	/* send to stdio command */
	page[3] = write(pfd[1], (void *)(page + 1024), page[3]);
	goto again;
      }
      case '<': {
	/* receive from stdio command */
	page[3] = read(pfd[2], (void *)(page + 1024), page[3]);
	goto again;
      }
      }
    noluck:
      munmap((void *)page, 16384);
    }

  exit(1);
}
