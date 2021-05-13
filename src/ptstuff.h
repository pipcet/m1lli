#include <stdbool.h>

#define ARRAYELTS(x) ((sizeof(x)/sizeof((x)[0])))

typedef unsigned u32;
typedef unsigned long u64;

static unsigned long dummybuf[16384];
static void *mapped;
static unsigned long offset;
static int fd = -1;
static unsigned long ppage = 0xb90000000;

static inline void remap_memory(unsigned long off)
{
  if (fd < 0)
    fd = open("/dev/mem", O_RDWR);
  if (mapped)
    munmap(mapped, 16384);
  void *new_mapped =
    mmap(NULL, 16384, PROT_READ|PROT_WRITE, MAP_SHARED, fd, off);
  if (new_mapped && new_mapped != MAP_FAILED) {
    mapped = new_mapped;
    offset = off;
  } else {
    mapped = dummybuf;
    offset = off;
  }
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

static inline u32 read32(unsigned long off)
{
  if (mapped && off >= offset && off < offset + 16384) {
    return *(volatile unsigned*)(mapped + off - offset);
  } else {
    remap_memory(off & ~16383L);
    return read32(off);
  }
}

static inline void write32(unsigned long off, u32 val)
{
  if (mapped && off >= offset && off < offset + 16384) {
    *(volatile unsigned*)(mapped + off - offset) = val;
  } else {
    remap_memory(off & ~16383L);
    write32(off, val);
  }
}

unsigned long alloc_page(void)
{
  unsigned long ret = read64(0xb90003e10);
  write64(0xb90003e10, ret + 16384);
  return ret;
}

unsigned long install_page(unsigned long va, unsigned long pa, bool executable)
{
  unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned long off1 = (va >> (14 + 11)) & 2047;
  unsigned long off2 = (va >> (14)) & 2047;

  unsigned long level0 = read64(ppage + 0x3e08);
 again:
  if (!(read64(level0 + off0 * 8) & 1)) {
    write64(level0 + off0 * 8, alloc_page() | 3);
    goto again;
  }
  unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
  if (!(read64(level1 + off1 * 8) & 1)) {
    write64(level1 + off1 * 8, alloc_page() | 3);
    goto again;
  }
  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
  write64(level2 + off2 * 8, pa | (executable ? 0x40000000000683 : 0x60000000000603));

  return pa;
}

unsigned long offs_to_va(unsigned long off0, unsigned long off1, unsigned long off2)
{
  return 0xffff000000000000 + (off0 << (14 + 11 + 11)) + (off1 << (14 + 11)) + (off2 << 14);
}

unsigned insn_at_va(unsigned long va, unsigned long level0)
{
  if ((va & 0xffff000000000000) != 0xffff000000000000)
    return 0;
  unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned long off1 = (va >> (14 + 11)) & 2047;
  unsigned long off2 = (va >> (14)) & 2047;

  if (!(read64(level0 + off0 * 8) & 1))
    return -1;
  unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
  if (!(read64(level1 + off1 * 8) & 1))
    return -2;
  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
  if (!(read64(level2 + off2 * 8) & 1))
    return -3;
  unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
  return read32(level3 + (va & 0x3ffc));
}

unsigned read32_at_va(unsigned long va, unsigned long level0)
{
  if ((va & 0xffff000000000000) != 0xffff000000000000)
    return 0;
  unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned long off1 = (va >> (14 + 11)) & 2047;
  unsigned long off2 = (va >> (14)) & 2047;

  if (!(read64(level0 + off0 * 8) & 1))
    return 0;
  unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
  if (!(read64(level1 + off1 * 8) & 1))
    return 0;
  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
  if (!(read64(level2 + off2 * 8) & 1))
    return 0;
  unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
  return read32(level3 + (va & 0x3ffc));
}

u64 read64_at_va(unsigned long va, unsigned long level0)
{
  if ((va & 0xffff000000000000) != 0xffff000000000000)
    return 0;
  unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned long off1 = (va >> (14 + 11)) & 2047;
  unsigned long off2 = (va >> (14)) & 2047;

  if (!(read64(level0 + off0 * 8) & 1))
    return 0;
  unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
  if (!(read64(level1 + off1 * 8) & 1))
    return 0;
  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
  if (!(read64(level2 + off2 * 8) & 1))
    return 0;
  unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
  return read64(level3 + (va & 0x3ff8));
}

void write64_to_va(unsigned long va, u64 val, unsigned long level0)
{
  if ((va & 0xffff000000000000) != 0xffff000000000000)
    return;
  unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned long off1 = (va >> (14 + 11)) & 2047;
  unsigned long off2 = (va >> (14)) & 2047;

  if (!(read64(level0 + off0 * 8) & 1))
    return;
  unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
  if (!(read64(level1 + off1 * 8) & 1))
    return;
  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
  if (!(read64(level2 + off2 * 8) & 1))
    return;
  unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
  write64(level3 + (va & 0x3ff8), val);
}

struct stackframe {
  unsigned long x[32]; /* x29, x30 not valid! */
};

u64 read_reg(unsigned long frame, unsigned long index, unsigned long ttb)
{
  return read64_at_va(frame + 8 * index, ttb);
}

void write_reg(unsigned long frame, unsigned long index, u64 val,
	       unsigned long ttb)
{
  write64_to_va(frame + 8 * index, val, ttb);
}
