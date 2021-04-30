#include "snippet.h"

START_SNIPPET {
  unsigned long pc_plus_page;
  asm volatile("adrp %0, . + 16384" : "=r" (pc_plus_page));
  {
    unsigned long image = (pc_plus_page & ~16383);
    unsigned long minus_delta = image & ((1<<21) - 1);
    unsigned long size = ((unsigned long *)image)[2];
    __int128 *p = (void *)image + size;
    while (p != (__int128 *)(pc_plus_page - 16384)) {
      p--; p[-minus_delta/16] = *p;
    }
    asm volatile("br %0" : : "r" (image - minus_delta));
  }
} END_SNIPPET
