#include <stdbool.h>

struct commpage {
  unsigned long code[0x3000/8];
  unsigned long mmio_master; /* 0x3e00 */
  unsigned long mmio_ttbr; /* 0x3e08 */
  unsigned long pt_wait_flag; /* 0x3f00 */
  unsigned long mmio_reg_ptr; /* 0x3fb0 */
  unsigned long mmio_read_va; /* 0x3fb8 */
  unsigned long mmio_success; /* 0x3fd0 */
  unsigned long mmio_ttbr1; /* 0x3fe0 */
  unsigned long mmio_ttbr2; /* 0x3fe8 */
  unsigned long mmio_far; /* 0x3ff0 */
  unsigned long mmio_elr; /* 0x3ff8 */
};

#define ARRAYELTS(x) ((sizeof(x)/sizeof((x)[0])))

typedef unsigned u32;
typedef unsigned long u64;

static struct {
  void *mapped;
  unsigned long offset;
} mapping[32];

static int fd = -1;
static unsigned long ppage = 0xb90000000;

static inline void remap_memory(unsigned long off)
{
  if (fd < 0)
    fd = open("/dev/mem", O_RDWR);
  size_t i = 0;
  for (i = 0; i < ARRAYELTS(mapping); i++) {
    if (mapping[i].mapped == NULL) {
      mapping[i].mapped = mmap(NULL, 16384, PROT_READ|PROT_WRITE, MAP_SHARED, fd, off);
      if (mapping[i].mapped == MAP_FAILED)
	mapping[i].mapped = NULL;
      mapping[i].offset = off;
      return;
    }
  }
  i = random() % ARRAYELTS(mapping);
  munmap(mapping[i].mapped, 16384);
  mapping[i].mapped = NULL;
  mapping[i].offset = 0;
  remap_memory(off);
}

static void *remapped_addr(unsigned long off)
{
  asm volatile("isb");
  static long dummy = 0;
  for (size_t i = 0; i < ARRAYELTS(mapping); i++) {
    if (mapping[i].mapped && off >= mapping[i].offset && off < mapping[i].offset + 16384) {
      return (mapping[i].mapped + off - mapping[i].offset);
    }
  }
  remap_memory(off & ~16383L);
  for (size_t i = 0; i < ARRAYELTS(mapping); i++) {
    if (mapping[i].mapped && off >= mapping[i].offset && off < mapping[i].offset + 16384) {
      return (mapping[i].mapped + off - mapping[i].offset);
    }
  }
  return &dummy;
}

static inline u64 read64(unsigned long off)
{
  return *(volatile long *)remapped_addr(off);
}

static inline void write64(unsigned long off, u64 val)
{
  *(volatile long *)remapped_addr(off) = val;
}

static inline u32 read32(unsigned long off)
{
  return *(volatile unsigned*)remapped_addr(off);
}

static inline void write32(unsigned long off, u32 val)
{
  *(volatile unsigned *)remapped_addr(off) = val;
}

unsigned long alloc_page(void)
{
  unsigned long ret = read64(0xb90003e10);
  write64(0xb90003e10, ret + 16384);
  return ret;
}

unsigned long install_page(unsigned long va, unsigned long pa, int typeidx,
			    unsigned long level0)
{
  unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned long off1 = (va >> (14 + 11)) & 2047;
  unsigned long off2 = (va >> (14)) & 2047;

  level0 &= 0xffffffff000;
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
  unsigned long types[] = {
    0x0060000000000603,
    0x0040000000000683,
    0x006000000000040f,
    0x046000000000040f,
  };
  write64(level2 + off2 * 8, pa | (types[typeidx]));

  return pa;
}

unsigned long offs_to_va(unsigned long off0, unsigned long off1, unsigned long off2)
{
  return 0xffff000000000000 + (off0 << (14 + 11 + 11)) + (off1 << (14 + 11)) + (off2 << 14);
}

unsigned long va_to_pa(unsigned long va, unsigned long level0)
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
  if ((read64(level1 + off1 * 8) & 3) == 1) {
    unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
    return read32(level2 + (va & 0x3ffc) + (va & 0x1ffc000));
  }
  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
  if (!(read64(level2 + off2 * 8) & 1))
    return -3;
  unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
  return level3 + (va & 0x3fff);
}

unsigned long va_to_baseoff(unsigned long va, unsigned long level0)
{
  return va_to_pa(va, level0) - read64(0xac0000008);
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
  if ((read64(level1 + off1 * 8) & 3) == 1) {
    unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
    return read32(level2 + (va & 0x3ffc) + (va & 0x1ffc000));
  }
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
  if ((read64(level1 + off1 * 8) & 3) == 1) {
    unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
    return level2 + (va & 0x3ffc) + (va & 0x1ffc000);
  }
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

