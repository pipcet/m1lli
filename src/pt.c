#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

unsigned long level0_ttbr(void)
{
  return 0x8070c8000;
}

unsigned long level1_ptep(unsigned long va)
{
}

unsigned long level2_ptep(unsigned long va)
{
}

unsigned long level3_ptep(unsigned long va)
{
}

unsigned long offs_to_va(unsigned long off0, unsigned long off1, unsigned long off2)
{
  return 0xffff000000000000 + (off0 << (14 + 11 + 11)) + (off1 << (14 + 11)) + (off2 << 14);
}

int main(int argc, char **argv)
{
  unsigned long addr = 0;
  if (argv[2]) {
    addr = strtoll(argv[2], NULL, 0);
  }
  if (strcmp(argv[1], "va-for-pa") == 0) {
    unsigned long pa = addr;
    unsigned long level0 = level0_ttbr();
    unsigned long off0, off1, off2;
    for (off0 = 0; off0 < 2048; off0++) {
      if (!(read64(level0 + off0 * 8) & 1))
	continue;
      unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
      for (off1 = 0; off1 < 2048; off1++) {
	if (!(read64(level1 + off1 * 8) & 1))
	  continue;
	unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
	for (off2 = 0; off2 < 2048; off2++) {
	  if (!(read64(level2 + off2 * 8) & 1))
	    continue;

	  unsigned long pte = read64(level2 + off2 * 8) & 0xfffffff000;
	  if (pte == pa) {
	    printf("%016llx\n", offs_to_va(off0, off1, off2));
	  }
	}
      }
    }
  } else if (strcmp(argv[1], "pa-for-va") == 0) {
    unsigned long va = addr;
    unsigned long off0 = (addr >> (14 + 11 + 11)) & 2047;
    unsigned long off1 = (addr >> (14 + 11)) & 2047;
    unsigned long off2 = (addr >> (14)) & 2047;
    unsigned long level0 = level0_ttbr();
    if (!(read64(level0 + off0 * 8) & 1))
      return;
    unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
    if (!(read64(level1 + off1 * 8) & 1))
      return;
    unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
    if (!(read64(level2 + off2 * 8) & 1))
      return;
    unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
    printf("%016lx\n", level3);
  } else if (strcmp(argv[1], "map-va-to-pa-rw") == 0) {
  } else if (strcmp(argv[1], "map-va-to-pa-rx") == 0) {
  } else if (strcmp(argv[1], "unmap-va") == 0) {
  }

  return 0;
}
