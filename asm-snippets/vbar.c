#include "snippet.h"

START_SNIPPET {
  asm volatile("msr VBAR_EL1, %0" : : "r" (0xa00000000));
} END_SNIPPET
