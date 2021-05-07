#include "snippet.h"
#include <stdint.h>

void fadescreen(void)
{
  volatile unsigned * framebuffer = (void *)0xbdf438000;
  register unsigned long sctlr;
  asm volatile("mrs %0, SCTLR_EL1" : "=r" (sctlr));
  sctlr &= ~(0x1L);
  asm volatile("msr SCTLR_EL1, %0" : : "r" (sctlr));
  asm volatile("msr DAIF, %0" : : "r" (0x3c0L));
  asm volatile("msr VBAR_EL1, %0" : : "r" (0xa00000000));
  unsigned flag2 = 16, flag;
  while (flag2--) {
    for (unsigned x = 2560/2; x < 2560; x++) {
      flag = 1000000;
      while (flag--)
	asm volatile("" : "=r" (flag) : "0" (flag));
      for (unsigned y = 0; y < 1600; y++) {
	  int r = ((framebuffer[y * 2560 + x] >> 20) & 0x3ff);
	  int g = ((framebuffer[y * 2560 + x] >> 10) & 0x3ff);
	  int b = ((framebuffer[y * 2560 + x] >>  0) & 0x3ff);
	  if (r) r--;
	  if (g) g--;
	  if (b) b--;
	  framebuffer[y * 2560 + x] ^= 0xffffffff;
      }
    }
  }
  while (1)
  for (char *p = 0x800000000; p < 0xb00000000; p++) {
#if 0
    if (p[0] == '2' &&
	p[1] == 'u' &&
	p[2] == 'k' &&
	p[3] == '5' &&
	p[4] == '3' &&
	p[5] == '1' &&
	p[6] == 'a' &&
	p[7] == 'z')
#endif
      {
      //*(volatile unsigned *)(0x235044000) = 0;
      //volatile unsigned *)(0x23d2b0014) = 0x100000;
      //volatile unsigned *)(0x23d2b0010) = 0;
      //volatile unsigned *)(0x23d2b001c) = 4;
      unsigned long x0 = *(unsigned long *)0xb20000000;
      ((void (*)(unsigned long))0xb20010800)(x0);
    }
  }
  fadescreen();
}
