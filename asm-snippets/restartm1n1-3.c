#include "snippet.h"
#include <stdint.h>

#define AIC_TIMER 0x23b108020

extern inline void udelay(u32 d)
{
    u32 delay = d * 24;
    u32 val = read32(AIC_TIMER);
    while ((read32(AIC_TIMER) - val) < delay)
        ;
}


  void f(void) __attribute__((noinline));
  void f(void) {
    volatile unsigned * framebuffer = (void *)0xbdf438000;
    volatile unsigned long *start_of_mem = (void *)0x800000000;
    volatile unsigned long *end_of_mem = (void *)0x900000000;
    register unsigned long foo = (1L<<27) * 50 * 4;
    register unsigned long sctlr;
    asm volatile("mrs %0, SCTLR_EL1" : "=r" (sctlr));
    sctlr &= ~(0x1);
    asm volatile("msr SCTLR_EL1, %0" : : "r" (sctlr));
    asm volatile("msr DAIF, %0" : : "r" (0x3c0L));
    asm volatile("msr VBAR_EL1, %0" : : "r" (0xa00000000));
    asm volatile("adr %0, 1f\n\tbr %0\n\t1: nop" : "=r" (sctlr));
    while (foo) {
      while (foo--) {
	if ((foo & 65535) == 0)
	  framebuffer[800 * 2560 + 2560/2] = foo;
	asm volatile("nop\n\tnop" : "=&r" (foo) : "0" (foo));
      }
      *(volatile unsigned *)(0x23d2b0014) = 0x100000;
      *(volatile unsigned *)(0x23d2b0010) = 0;
      *(volatile unsigned *)(0x23d2b001c) = 4;
      asm volatile("" : "=&r" (foo) : "0" (foo));
    }
  }

START_SNIPPET {
  f();
} END_SNIPPET
