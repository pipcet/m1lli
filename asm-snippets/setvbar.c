#include "snippet.h"

// c0c3e4 c0c100
void setvbar(void)
{
  long vbar = (((long)__builtin_return_address(0)) & -4096L) - 0x3000;
  *(long *)0xa00002080 = vbar;
  asm volatile("msr vbar_el1, %0" : : "r" (vbar));
}
