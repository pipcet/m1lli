#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

typedef unsigned long u64;

static void *mapped;
static unsigned long offset;
static int fd = -1;

static inline void remap_memory(unsigned long off)
{
  while (fd < 0)
    fd = open("/dev/mem", O_RDWR);
  mapped = mmap(NULL, 16384, PROT_READ|PROT_WRITE, MAP_SHARED, fd, off);
  offset = off;
}

static inline u64 read64(unsigned long off)
{
  if (mapped && off >= offset && off < offset + 16384) {
    return *(volatile long *)(mapped + off - offset);
  } else {
    remap_memory(off & ~16383L);
    return read64(off);
  }
}

static inline void write64(unsigned long off, u64 val)
{
  if (mapped && off >= offset && off < offset + 16384) {
    *(volatile long *)(mapped + off - offset) = val;
  } else {
    remap_memory(off & ~16383L);
    write64(off, val);
  }
}

int main(void)
{
  unsigned long ppage = 0xb90000000;
  write64(ppage + 0x3ff8, 0xffffffff);
  write64(ppage + 0x3ff0, 0);
  unsigned long far;

  while (true) {
    bool success = false;
    while ((far = read64(ppage + 0x3ff0)) == 0);
    do {
      unsigned long elr = read64(ppage + 0x3ff8);

      printf("FAR %016lx ELR %016lx\n", far, elr);

      unsigned long va = far;
      unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
      unsigned long off1 = (va >> (14 + 11)) & 2047;
      unsigned long off2 = (va >> (14)) & 2047;
      unsigned long level0 = read64(ppage + 0x3fe0);
      if (!(read64(level0 + off0 * 8) & 1))
	break;
      unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
      if (!(read64(level1 + off1 * 8) & 1))
	break;
      unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
      if (!(read64(level2 + off2 * 8) & 1)) {
	write64(level2 + off2 * 8, read64(level2 + off2 * 8) | 1);
	success = true;
      }
      unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
      printf("PA %016lx\n", level3);
    } while (0);

    write64(ppage + 0x3ff8, success);
    write64(ppage + 0x3ff0, 0);
  }
}
