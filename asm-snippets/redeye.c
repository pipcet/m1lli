#include "snippet.h"

void redeye(void) {
  volatile unsigned * framebuffer = (void *)0xbdf438000;
  unsigned x = 2560 / 2;
  unsigned y = 800 / 2;
  volatile unsigned count = 0;
  do {
    while (count) {
      framebuffer[y * 2560 + x] = count++;
    }
    count = 1;
  } while (count);
}
