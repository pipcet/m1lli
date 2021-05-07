#include "snippet.h"
#include <stdint.h>

START_SNIPPET {
  volatile unsigned long *start_of_mem = (void *)0x800000000;
  volatile unsigned long *end_of_mem = (void *)0x900000000;
  unsigned flag = 1;

  while (flag) {
    asm volatile("" : "=r" (flag) : "0" (flag));
    for (volatile unsigned long *p = start_of_mem; p < end_of_mem; p += 16384 / sizeof(long))
      if (*p == 0xdeaddeaddeaddead) {
	*(unsigned *)(0x23d2b0014) = 0x100000;
	*(unsigned *)(0x23d2b0010) = 0;
	*(unsigned *)(0x23d2b001c) = 4;
	while (1) ;
      }
  }
} END_SNIPPET
