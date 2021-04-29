#include "snippet.h"

START_SNIPPET {
  unsigned long pc;
  asm volatile("adr %0, ." : "=r" (pc));
  unsigned long page = (pc & ~16383) + 16384;
  unsigned long newpage = page & -(1 << 21);
  if (page != newpage) {
    newpage += 1 << 21;
    unsigned long size = ((unsigned long *)page)[2];
    __int128 *p = (void *)page + size;
    while (p != (__int128 *)page) {
      p[(newpage - page)/16] = *p; p--;
    }
    asm volatile("br %0" : : "r" (newpage + pc - page - 16384));
    __builtin_unreachable();
  }
} END_SNIPPET
