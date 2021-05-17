#include "snippet.h"
#include <stdint.h>

#define AIC_TIMER 0x23b108020
typedef uint32_t u32;
#define read32(addr) (*(volatile u32 *)(addr))
static inline void udelay(unsigned long d)
{
  unsigned long t0;
  asm volatile("mrs %0, CNTPCT_EL0" : "=r" (t0));
  unsigned long val;
  do {
    asm volatile("mrs %0, CNTPCT_EL0" : "=r" (val));
    asm volatile("isb");
  } while (val - t0 < d * 24);
}

void fadescreen(void)
{
  volatile unsigned * framebuffer = (void *)0xbdf438000;
  register unsigned long sctlr;
  /* disable MMU. We need to do this since our page tables are about to
   * be overwritten by MacOS */
  asm volatile("mrs %0, SCTLR_EL1" : "=r" (sctlr));
  sctlr &= ~(0x1L);
  asm volatile("msr SCTLR_EL1, %0" : : "r" (sctlr));
  /* Clear interrupts, just in case. */
  asm volatile("msr DAIF, %0" : : "r" (0x3c0L));
  //asm volatile("msr VBAR_EL1, %0" : : "r" (0xac0010000));
  /* 10 second delay, so MacOS isn't confused by us. */
  //udelay(10 * 1000000L);
  unsigned long x0 = *(unsigned long *)0xac0000000;
  return ((void (*)(unsigned long, unsigned long))0xa40002000)(x0, 0);
}
