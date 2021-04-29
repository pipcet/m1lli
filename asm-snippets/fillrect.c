#include "snippet.h"
#include <stdint.h>

START_SNIPPET {
  unsigned * framebuffer = (void *)0xbdf438000;
  for (unsigned x = 0; x < 2560; x++) {
    for (unsigned y = 0; y < 800; y++) {
      framebuffer[y * 2560 + x] = y; //((*arg)&(1 << (x & 31))) ? 0xffffff : 0;
    }
  }
} END_SNIPPET
