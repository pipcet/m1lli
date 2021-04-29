#include "snippet.h"
#include <stdint.h>

START_SNIPPET {
  *(volatile uint32_t *)0x23d2b0010 = 0;
  *(volatile uint32_t *)0x23d2b0014 = 0;
  *(volatile uint32_t *)0x23d2b001c = 4;
} END_SNIPPET
