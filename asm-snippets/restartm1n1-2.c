#include "snippet.h"
#include <stdint.h>

#define AIC_TIMER 0x23b108020
typedef unsigned int u32;
#define read32(addr) (*(volatile u32 *)(addr))
extern inline void udelay(u32 d)
{
    u32 delay = d * 24;
    u32 val = read32(AIC_TIMER);
    while ((read32(AIC_TIMER) - val) < delay)
        ;
}


void f(void) __attribute__((noinline));
void f(void) {
  for (int i = 0; i < 15; i++)
    udelay (1000000);
  *(volatile unsigned *)(0x23d2b0014) = 0x100000;
  *(volatile unsigned *)(0x23d2b0010) = 0;
  *(volatile unsigned *)(0x23d2b001c) = 4; 
}

START_SNIPPET {
  f();
} END_SNIPPET
