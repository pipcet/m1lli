#include <map>
#include <sched.h>
#include <set>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "../asm-snippets/delay-loop..h"
#include "../asm-snippets/expose-ttbr-2..h"
#include "../asm-snippets/expose-ttbr-to-stack..h"
#include "../asm-snippets/expose-ttbr..h"
#include "../asm-snippets/infloop..h"
#include "../asm-snippets/irq-handler-store-magic-cookie..h"
#include "../asm-snippets/irq-handler-store-ttbr..h"
#include "../asm-snippets/new-irq-handler-part1..h"
#include "../asm-snippets/new-irq-handler-part2..h"
#include "../asm-snippets/new-vbar-entry-for-mrs..h"
#include "../asm-snippets/new-vbar-entry-special..h"
#include "../asm-snippets/new-vbar-entry..h"
#include "../asm-snippets/optimized-putc..h"
#include "../asm-snippets/wait-for-confirmation-receiver-part2..h"
#include "../asm-snippets/wait-for-confirmation-receiver..h"
#include "../asm-snippets/wait-for-confirmation..h"

#define MAGIC_WORD 0x140008b6b5fffff8
#define U64_MAX 0xffffffffffffffff
#define PAGE_SIZE (16384L)
#define PAGE_TABLE_PAGE_MASK (0xfffffff000UL)
#define MASK_T (0x1f)
#define MASK_N (0x1f << 5)

typedef unsigned u32;
typedef unsigned long u64;

class va_for_pa {
public:
  u64 pt;
  u64 va;
};

std::multimap<u64,va_for_pa> pa_to_va;

struct commpage {
  unsigned long code[0x3000/8];
  unsigned long mmio_master; /* 0x3e00 */
  unsigned long mmio_ttbr; /* 0x3e08 */
  unsigned long boot_master; /* 0x3e88 */
  unsigned long pt_wait_flag; /* 0x3f00 */
  unsigned long pt_stolen_flag; /* 0x3f08 */
  unsigned long mmio_self_ptr; /* 0x3fa0 */
  unsigned long mmio_offset; /* 0x3fa8 */
  unsigned long mmio_reg_ptr; /* 0x3fb0 */
  unsigned long mmio_read_va; /* 0x3fb8 */
  unsigned long mmio_frame; /* 0x3fc8 */
  unsigned long mmio_success; /* 0x3fd0 */
  unsigned long mmio_esr; /* 0x3fd8 */
  unsigned long mmio_ttbr0; /* 0x3fe0 */
  unsigned long mmio_ttbr1; /* 0x3fe8 */
  unsigned long mmio_far; /* 0x3ff0 */
  unsigned long mmio_elr; /* 0x3ff8 */
};

#define ARRAYELTS(x) ((sizeof(x)/sizeof((x)[0])))

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
      return (void *)((char *)mapping[i].mapped + off - mapping[i].offset);
    }
  }
  remap_memory(off & ~16383L);
  for (size_t i = 0; i < ARRAYELTS(mapping); i++) {
    if (mapping[i].mapped && off >= mapping[i].offset && off < mapping[i].offset + 16384) {
      return (void *)((char *)mapping[i].mapped + off - mapping[i].offset);
    }
  }
  return &dummy;
}

volatile int global_sigbus_flag;

static inline u64 read64(unsigned long off)
{
  global_sigbus_flag = 0;
  u64 ret = *(volatile long *)remapped_addr(off);
  if (global_sigbus_flag) {
    fprintf(stderr, "received SIGBUS for off %016lx\n", off);
    ret = 0;
  }
  asm volatile("isb");
  asm volatile("dmb sy");
  asm volatile("dsb sy");
  return ret;
}

static inline void write64(unsigned long off, u64 val)
{
  //printf("write64 %016lx <- %016lx\n", off, val);
  global_sigbus_flag = 0;
  *(volatile long *)remapped_addr(off) = val;
  if (global_sigbus_flag) {
    fprintf(stderr, "received SIGBUS for off %016lx\n", off);
  }
}

static inline u32 read32(unsigned long off)
{
  global_sigbus_flag = 0;
  u32 ret = *(volatile unsigned*)remapped_addr(off);
  if (global_sigbus_flag) {
    fprintf(stderr, "received SIGBUS for off %016lx\n", off);
  }
  return ret;
}

static inline void write32(unsigned long off, u32 val)
{
  global_sigbus_flag = 0;
  *(volatile unsigned *)remapped_addr(off) = val;
  if (global_sigbus_flag) {
    fprintf(stderr, "received SIGBUS for off %016lx\n", off);
  }
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
    write64(level0 + off0 * 8, alloc_page() | 3 /* | 0x1800000000000000 */);
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
    0x0040000000000683, /* executable. testing. nope.  */
    0x006000000000040f,
    0x046000000000040f,
    0x0050000000000683, /* executable (?) doesn't work */
    0x0020000000000603,
    0x0000000000000603, /* testing. */
    0x006000000000040f, /* testing. Doesn't work. */
    0x0060000000000607,
    0x0460000000000603, /* testing. Doesn't work. */
  };
  write64(level2 + off2 * 8, pa | (types[typeidx]));

  return pa;
}

unsigned long offs_to_va(unsigned long off0, unsigned long off1, unsigned long off2, int high)
{
  return (high ? 0xffff800000000000 : 0) + (off0 << (14 + 11 + 11)) + (off1 << (14 + 11)) + (off2 << 14);
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

  if (!(read64(level0 + off0 * 8) & 1)) {
    //fprintf(stderr, "no level0!\n");
    return 0;
  } else {
    //fprintf(stderr, "level0 %016lx!\n", read64(level0 + off0 * 8));
  }
  unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
  if (!(read64(level1 + off1 * 8) & 1)) {
    fprintf(stderr, "no level1!\n");
    return 0;
  } else {
    //fprintf(stderr, "level1 %016lx!\n", read64(level1 + off1 * 8));
  }
  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
  if (!(read64(level2 + off2 * 8) & 1)) {
    fprintf(stderr, "no level2!\n");
    return 0;
  } else {
    //fprintf(stderr, "level2 %016lx!\n", read64(level2 + off2 * 8));
  }
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

bool write64_to_va(unsigned long va, u64 val, unsigned long level0)
{
  if ((va & 0xffff000000000000) != 0xffff000000000000)
    return false;
  unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned long off1 = (va >> (14 + 11)) & 2047;
  unsigned long off2 = (va >> (14)) & 2047;

  if (!(read64(level0 + off0 * 8) & 1))
    return false;
  unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
  if (!(read64(level1 + off1 * 8) & 1))
    return false;
  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
  if (!(read64(level2 + off2 * 8) & 1))
    return false;
  unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
  write64(level3 + (va & 0x3ff8), val);
  return true;
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
  if (!write64_to_va(frame + 8 * index, val, ttb))
    abort();
}

#define PAGE_RW 0 /* not 0, 6 */

unsigned long level0_ttbr(void)
{
  return read64(0xb90003e08);
}

void iterate_pt(unsigned long level0, void (*f)(unsigned long pte, unsigned long va,
						int level, void *cookie), void *cookie)
{
  unsigned long off0, off1, off2;
  for (off0 = 0; off0 < 2048; off0++) {
    unsigned long pte1 = read64(level0 + off0 * 8);
    if (!(pte1 & 1))
      continue;
    unsigned long level1 = pte1 & 0xfffffff000;
    for (off1 = 0; off1 < 2048; off1++) {
      unsigned long pte2 = read64(level1 + off1 * 8);
      if ((pte2 & 3) == 1) {
	f(pte2, offs_to_va(off0, off1, 0, 1), 2, cookie);
	continue;
      }
      if (!(pte2 & 1))
	continue;
      unsigned long level2 = pte2 & 0xfffffff000;
      for (off2 = 0; off2 < 2048; off2++) {
	unsigned long pte3 = read64(level2 + off2 * 8);

	f(pte3, offs_to_va(off0, off1, off2, 1), 3, cookie);
      }
    }
  }
}

static unsigned long seen_tags[32] = { 0, };
static unsigned long seen_counts[32] = { 0, };
static void f2(unsigned long pte, unsigned long va, int level, void *cookie)
{
  unsigned long ptepa = pte & 0xfffffff000;
  unsigned long tags = pte &~ ptepa;
  int i;
  for (i = 0; i < 32; i++) {
    if (tags == seen_tags[i]) {
      seen_counts[i]++;
      return;
    }
    if (!seen_tags[i])
      break;
  }
  if (i < 32) {
    seen_tags[i] = tags;
    seen_counts[i]++;
  }
  printf("%016llx %016llx %d\n", va, pte, level);
}

void dump_pt_compressed(unsigned long level0)
{
  memset(seen_tags, 0, sizeof seen_tags);
  memset(seen_counts, 0, sizeof seen_counts);
  iterate_pt(level0, f2, NULL);
  for (int i = 0; i < 16; i++) {
    printf("%016lx: %ld\n", seen_tags[i], seen_counts[i]);
  }
}

static void f(unsigned long pte, unsigned long va, int level, void *cookie)
{
  static unsigned long seen_tags[16] = { 0, };
  if (!(pte & 1))
    return;
  unsigned long ptepa = pte & 0xfffffff000;
  unsigned long tags = pte &~ ptepa;
  int i;
  for (i = 0; i < 16; i++) {
    if (!seen_tags[i])
      break;
  }
  if (i < 16)
    seen_tags[i] = tags;
  printf("%016llx %016llx %d\n", va, pte, level);
}

void dump_pt(unsigned long level0)
{
  iterate_pt(level0, f, NULL);
}

static FILE *log;
static FILE *pt_log;
static FILE *mmio_log;

#define print(log, fmt, ...) do {					\
    struct timeval tv;							\
    gettimeofday(&tv, NULL);						\
    fprintf(log, "[%16ld.%06ld] " fmt, (long)tv.tv_sec, (long)tv.tv_usec, __VA_ARGS__); \
    fflush(log);							\
    fprintf(stderr, "[%16ld.%06ld] " fmt, (long)tv.tv_sec, (long)tv.tv_usec, __VA_ARGS__); \
  } while (0)

typedef unsigned __int128 u128;

class mmio_pterange;
class mmio_pterange {
public:
  u64 ttbr;
  u64 pa0; /* mapped physical address, 0 for table */
  u64 pt0; /* mapped page table physical address, 0 for page entry */
  u64 va0;
  u64 ptep;
  u64 pte;

  int level;
  unsigned long off0;
  unsigned long off1;
  unsigned long off2;

  u64 size()
  {
    switch (level) {
    case 3:
      return PAGE_SIZE;
    case 2:
      return PAGE_SIZE << 11;
    case 1:
      return PAGE_SIZE << 22;
    case 0:
      return PAGE_SIZE << 33;
    }
    return 0;
  }

  std::string describe()
  {
    char *str;
    asprintf(&str, "range at level %d covering %016lx-%016lx; pte %016lx",
	     level, va0, va0 + size(), pte);

    return std::string(str);
  }


  std::vector<u64> pages()
  {
    std::vector<u64> ret;
    if (!pa0)
      return ret;
    u64 size = 1;
    if (level == 2)
      size = 1 << 11;
    if (level == 1)
      size = 1 << 22;
    for (u64 pa = pa0; pa < pa0 + size * 0x4000; pa += 0x4000)
      ret.push_back(pa);

    return ret;
  }

  std::vector<mmio_pterange> sub_ranges();

  mmio_pterange(u64 pa)
    : pa0(pa)
  {
  }
};


std::vector<mmio_pterange> mmio_pterange::sub_ranges()
{
  std::vector<mmio_pterange> ret;
  switch (level) {
  case 0:
    for (unsigned long off0 = 0; off0 < 2048; off0++) {
      u64 ptep = pt0 + off0 * 8;
      u64 pte = read64(ptep);
      mmio_pterange p(pte & PAGE_TABLE_PAGE_MASK);
      p.ttbr = ttbr;
      p.pa0 = 0;
      p.pt0 = 0;
      p.va0 = offs_to_va(off0, 0, 0, 1);
      p.ptep = ptep;
      p.pte = pte;
      p.level = 1;
      p.off0 = off0;
      p.off1 = 0;
      p.off2 = 0;
      if ((pte & 3) == 3) {
	p.pa0 = pte & PAGE_TABLE_PAGE_MASK;
	ret.push_back(p);
	for (auto r : p.sub_ranges())
	  ret.push_back(r);
      } else if (pte & 1) {
	p.pt0 = pte & PAGE_TABLE_PAGE_MASK;
	ret.push_back(p);
	for (auto r : p.sub_ranges())
	  ret.push_back(r);
      }
    }
    break;
  case 1:
    for (unsigned long off1 = 0; off1 < 2048; off1++) {
      u64 ptep = pt0 + off1 * 8;
      u64 pte = read64(ptep);
      mmio_pterange p(pte & PAGE_TABLE_PAGE_MASK);
      p.ttbr = ttbr;
      p.pa0 = 0;
      p.pt0 = 0;
      p.va0 = offs_to_va(off0, off1, 0, 1);
      p.ptep = ptep;
      p.pte = pte;
      p.level = 2;
      p.off0 = off0;
      p.off1 = off1;
      p.off2 = 0;
      if ((pte & 3) == 3) {
	p.pa0 = pte & PAGE_TABLE_PAGE_MASK;
	ret.push_back(p);
	for (auto r : p.sub_ranges())
	  ret.push_back(r);
      } else if (pte & 1) {
	p.pt0 = pte & PAGE_TABLE_PAGE_MASK;
	ret.push_back(p);
	for (auto r : p.sub_ranges())
	  ret.push_back(r);
      }
    }
    break;
  case 2:
    for (unsigned long off2 = 0; off2 < 2048; off2++) {
      u64 ptep = pt0 + off2 * 8;
      u64 pte = read64(ptep);
      mmio_pterange p(pte & PAGE_TABLE_PAGE_MASK);
      p.ttbr = ttbr;
      p.pa0 = 0;
      p.pt0 = 0;
      p.va0 = offs_to_va(off0, off1, off2, 1);
      p.ptep = ptep;
      p.pte = pte;
      p.level = 3;
      p.off0 = off0;
      p.off1 = off1;
      p.off2 = off2;
      if (pte & 1) {
	p.pa0 = pte & PAGE_TABLE_PAGE_MASK;
	ret.push_back(p);
      }
    }
    break;
  case 3:
    break;
  }

  return ret;
}

class mmio_insn {
public:
  u64 va;
  u64 elr;
  u64 level0;
  u64 frame;
  int size;

  u32 get_insn() {
    return insn_at_va(elr, level0);
  }
};

class mmio_va_range;
class mmio_pa_range {
public:
  size_t refcount;
  void deref()
  {
    refcount--;
    fprintf(stderr, "refcount now down to %ld\n", refcount);
  }

  void ref()
  {
    refcount++;
    fprintf(stderr, "refcount now %ld\n", refcount);
  }

  u64 pa;
  u64 pa_end;

  mmio_pa_range(u64 pa, u64 pa_end)
    : refcount(1), pa(pa), pa_end(pa_end)
  {
  }

  mmio_pa_range()
    : refcount(0), pa(0), pa_end(0)
  {
  }

  bool overlaps(u64 pa, u64 pa_end)
  {
    return pa < this->pa_end && this->pa < pa_end;
  }

  virtual bool still_valid()
  {
    return refcount > 0;
  }
  virtual std::string describe();
  virtual u64 load_u64(u64 pa);
  virtual void store_u64(u64 pa, u64 val);
  virtual void store(mmio_insn *insn, u64 pa, u128 val);
  virtual u128 load(mmio_insn *insn, u64 pa);
  virtual mmio_va_range *virtualize(u64 pa, u64 va, u64 va_end);
};

class mmio_pa_range_pa
  : public mmio_pa_range {
public:
  virtual std::string describe();
  virtual u64 load_u64(u64 pa);
  virtual void store_u64(u64 pa, u64 val);
  virtual u128 load(mmio_insn *insn, u64 pa);
  virtual void store(mmio_insn *insn, u64 pa, u128 val);

  mmio_pa_range_pa(u64 pa, u64 pa_end)
    : mmio_pa_range(pa, pa_end) {}
};

class mmio_pa_range_cache
  : public mmio_pa_range {
public:
  u64 *buf;

  mmio_pa_range_cache(u64 pa, u64 pa_end)
    : mmio_pa_range(pa, pa_end),
      buf(new u64[(pa_end - pa) / 8])
  {
    for (int i = 0; i < (pa_end - pa) / 8; i++)
      buf[i] = read64(pa + 8 * i);
  }

  virtual std::string describe();
  virtual u64 load_u64(u64 pa);
  virtual void store_u64(u64 pa, u64 val);
  virtual u128 load(mmio_insn *insn, u64 pa);
  virtual void store(mmio_insn *insn, u64 pa, u128 val);
};


void mmio_pa_range_cache::store(mmio_insn *insn, u64 pa, u128 val)
{
  u64 off = pa - this->pa;
  u64 index = off/8;
  int size = insn->size;
  if (size == 8)
    buf[index] = val;
  else if (size == 16) {
    buf[index] = val & U64_MAX;
    buf[index+1] = val >> 64;
  } else {
    memcpy(((char *)&buf[index]) + (off & 7), &val, size);
  }
}

u128 mmio_pa_range_cache::load(mmio_insn *insn, u64 pa)
{
  u64 off = pa - this->pa;
  u64 index = off/8;
  int size = insn->size;
  if (size == 8) {
    return buf[index];
  } else {
    u128 val = 0;
    memcpy((char *)&val, ((char *)&buf[index]) + (off & 7), size);
    return val;
  }
}

void mmio_pa_range_cache::store_u64(u64 pa, u64 val)
{
  u64 off = pa - this->pa;
  u64 index = off/8;
  buf[index] = val;
}

u64 mmio_pa_range_cache::load_u64(u64 pa)
{
  u64 off = pa - this->pa;
  u64 index = off/8;
  return buf[index];
}

class mmio_pa_range_fwd
  : public mmio_pa_range
{
public:
  mmio_pa_range *lower;
  virtual void store(mmio_insn *insn, u64 pa, u128 val);
  virtual u128 load(mmio_insn *insn, u64 pa);
  virtual std::string describe();
  mmio_pa_range_fwd(mmio_pa_range *lower)
    : lower(lower), mmio_pa_range(lower->pa, lower->pa_end) {}
};

void mmio_pa_range_fwd::store(mmio_insn *insn, u64 pa, u128 val)
{
  lower->store(insn, pa, val);
}

u128 mmio_pa_range_fwd::load(mmio_insn *insn, u64 pa)
{
  return lower->load(insn, pa);
}

std::string mmio_pa_range_fwd::describe()
{
  return lower->describe();
}

class mmio_pa_range_log
  : public mmio_pa_range_fwd
{
public:
  virtual void store(mmio_insn *insn, u64 pa, u128 val);
  virtual u128 load(mmio_insn *insn, u64 pa);
  mmio_pa_range_log(mmio_pa_range *lower)
    : mmio_pa_range_fwd(lower) {}
};

class mmio_pa_range_pt
  : public mmio_pa_range {
public:
  mmio_pterange pterange;
  mmio_pa_range *pa_range_pa;
  mmio_pa_range *pa_range_cache;

  virtual std::string describe();
  virtual u64 load_u64(u64 pa);
  virtual void store_u64(u64 pa, u64 val);
  virtual u128 load(mmio_insn *insn, u64 pa);
  virtual void store(mmio_insn *insn, u64 pa, u128 val);

  mmio_pa_range_pt(u64 pa, u64 pa_end, mmio_pterange pterange)
    : mmio_pa_range(pa, pa_end),
      //pa_range_pa(new mmio_pa_range_log(new mmio_pa_range_pa(pa, pa_end))),
      pa_range_pa(new mmio_pa_range_pa(pa, pa_end)),
      pa_range_cache(new mmio_pa_range_cache(pa, pa_end)),
      pterange(pterange)
  {
    while (pa < pa_end) {
      store_u64(pa, load_u64(pa));
      pa += 8;
    }
  }
};


class mmio_va_range {
public:
  mmio_pa_range *pa_range;
  u64 pa_offset;
  u64 va;
  u64 va_end;

  mmio_va_range(mmio_pa_range *pa_range, u64 pa_offset, u64 va, u64 va_end)
    : pa_range(pa_range), pa_offset(pa_offset), va(va), va_end(va_end)
  {
  }

  void force_remap()
  {
  }

  virtual std::string get_name()
  {
    return "unknown";
  }

  virtual void store(mmio_insn *insn, u128 val)
  {
    pa_range->store(insn, pa_offset + insn->va - va, val);
  }

  virtual u128 load(mmio_insn *insn)
  {
    return pa_range->load(insn, pa_offset + insn->va - va);
  }

  virtual u64 loggable_address(u64)
  {
    return 0xdeadbeef;
  }

  std::string describe()
  {
    char *str;
    if (pa_offset == 0) {
      asprintf(&str, "VA %016lx-%016lx %s %s",
	       va, va_end,
	       pa_range->describe().c_str(),
	       get_name().c_str());
    } else {
      asprintf(&str, "VA %016lx-%016lx %s+%016lx %s",
	       va, va_end,
	       pa_range->describe().c_str(),
	       pa_offset,
	       get_name().c_str());
    }
    std::string ret = str;
    return ret;
  }

  void dump()
  {
    print(mmio_log, "VA %016lx-%016lx %s\n", va, va_end, get_name().c_str());
  }

  bool handle_insn(mmio_insn *insn);
};

class mmio_pa_table
  : public std::map<u64,mmio_pa_range *> {
public:
  mmio_pa_range *find_range_overlapping(u64 pa, u64 pa_end)
  {
    for (auto pair : *this) {
      auto range = pair.second;
      if (range && range->overlaps(pa, pa_end))
	return range;
    }

    return nullptr;
  }

  mmio_pa_range *find_range(u64 pa)
  {
    return find_range_overlapping(pa, pa + 1);
    auto it = lower_bound(pa);
    if (it == begin())
      return nullptr;

    if (it != end())
      if (it->second->pa <= pa && pa < it->second->pa_end)
	return it->second;

    --it;

    if (it == begin())
      return nullptr;

    if (it->second->pa <= pa && pa < it->second->pa_end)
      return it->second;

    return nullptr;
  }

  mmio_pa_range *insert_range(mmio_pa_range *range) {
    return (*this)[range->pa] = range;
  }
};

class mmio_table
  : public std::multimap<u64,mmio_va_range *> {
public:
  mmio_va_range *find_range(u64 va)
  {
    mmio_va_range *ret = nullptr;
    for (auto it = begin(); it != end(); it++) {
      if (it->second->va <= va && va < it->second->va_end)
	if (ret == nullptr ||
	    (ret->va_end - ret->va) > (it->second->va_end - it->second->va))
	  ret = it->second;
    }

    return ret;
  }

  void insert_range(mmio_va_range *range)
  {
    mmio_va_range *oldrange = find_range(range->va);
    if (oldrange != nullptr)
      return;

    insert(std::make_pair(range->va, range));
  }

  void dump()
  {
    for (auto it : *this) {
      auto range = it.second;
      range->dump();
      sleep(1);
    }
  }
};

mmio_va_range *mmio_pa_range::virtualize(u64 pa, u64 va, u64 va_end)
{
  u64 off = pa;
  mmio_va_range *ret = new mmio_va_range(this, off, va, va_end);

  return ret;
}

static mmio_pa_table mmio_pa_ranges;
static mmio_table mmio_va_ranges;


std::string
mmio_pa_range_pt::describe()
{
  char *str;
  asprintf(&str, "[PT at %016lx for %016lx-%016lx]",
	   pa, pterange.va0, pterange.va0 + pterange.size());
  return str;
}

u128
mmio_pa_range_pt::load(mmio_insn *insn, u64 pa)
{
  //print(mmio_log, "faking load of %016lx\n", (long)pa_range_pa->load(insn, pa));
  return pa_range_cache->load(insn, pa);
}

u64
mmio_pa_range_pt::load_u64(u64 pa)
{
  //print(mmio_log, "faking load of %016lx\n", (long)pa_range_pa->load_u64(pa));
  return pa_range_cache->load_u64(pa);
}


void mmio_pa_range::store(mmio_insn *, u64, u128)
{
}

u128 mmio_pa_range::load(mmio_insn *, u64)
{
  return 0;
}

void mmio_pa_range::store_u64(u64, u64)
{
}

u64 mmio_pa_range::load_u64(u64)
{
  return 0;
}

std::string mmio_pa_range::describe()
{
  return "[no description]";
}

std::string mmio_pa_range_pa::describe()
{
  return "[PA]";
}

std::string mmio_pa_range_cache::describe()
{
  return "[cached]";
}

void mmio_pa_range_pa::store(mmio_insn *insn, u64 pa, u128 val)
{
  switch (insn->size) {
  case 4:
    write32(pa, (unsigned) val);
    return;
  case 16:
    write64(pa, (unsigned long) val);
    write64(pa + 8, (unsigned long) (val >> 64));
    return;
  case 8:
    write64(pa, (unsigned long) val);
    return;
  }
  print(mmio_log, "unhandled insn size %d\n", insn->size);
  abort();
}

u128
mmio_pa_range_pa::load(mmio_insn *insn, u64 pa)
{
  switch (insn->size) {
  case 4:
    return read32(pa);
  case 16: {
    u128 ret = read64(pa);
    ret += ((u128)read64(pa + 8) << 64);
    return ret;
  }
  case 8: {
    u64 ret = read64(pa);
    return ret;
  }
  }
  print(mmio_log, "unhandled insn size %d\n", insn->size);
  abort();
}

void mmio_pa_range_pa::store_u64(u64 pa, u64 val)
{
    write64(pa, (unsigned long) val);
}

u64
mmio_pa_range_pa::load_u64(u64 pa)
{
  u64 ret = read64(pa);
  return ret;
}

void
mmio_pa_range_pt::store_u64(u64 pa, u64 val)
{
  u64 prev_pte = pa_range_cache->load_u64(pa);
  if (pterange.level < 2 && (val & 3) == 3) {
    mmio_pa_range *newrange = mmio_pa_ranges.find_range(val & PAGE_TABLE_PAGE_MASK);
    mmio_pa_range *oldrange = mmio_pa_ranges.find_range(prev_pte & PAGE_TABLE_PAGE_MASK);
    if (newrange != oldrange) {
      if (newrange)
	newrange->ref();
      if (oldrange)
	oldrange->deref();
    }
  }
  pa_range_cache->store_u64(pa, val);

  if (pterange.level < 2) {
    //print(mmio_log, "high-level page table modified! %d\n", pterange.level);
    u64 pte = val;
    u64 off = (pa & 0x3ff8) / 8;
    if ((pte & 3) == 3) {
      u64 pt = val & PAGE_TABLE_PAGE_MASK;
      mmio_pterange pterange = this->pterange;
      pterange.level++;
      switch(this->pterange.level) {
      case 0:
	pterange.off0 += off; break;
      case 1:
	pterange.off1 += off; break;
      case 2:
	pterange.off2 += off; break;
      default:
	while (true)
	  print(mmio_log, "invalid pterange level %d\n", this->pterange.level);
	abort();
      }
      pterange.va0 = offs_to_va(pterange.off0, pterange.off1, pterange.off2,
				1);
      auto pt_range =
	new mmio_pa_range_log
	(new mmio_pa_range_pt(pt, pt + PAGE_SIZE, pterange));
      mmio_pa_ranges.insert_range(pt_range);
      print(mmio_log, "stored page table %016lx for %016lx\n", (long)val,
	    pterange.va0);
      pa_range_pa->store_u64(pa, val);
      return;
    } else if (pte & 1) {
      print(mmio_log, "unhandled large page at %016lx in %s\n", pa,
	    describe().c_str());
      pa_range_pa->store_u64(pa, val);
    } else {
      pa_range_pa->store_u64(pa, val);
    }
  }
  if (val & 1) {
    u64 pte = val;
    u64 mapped_pa = val & PAGE_TABLE_PAGE_MASK;
    u64 mapped_va = offs_to_va(pterange.off0,
			       pterange.off1,
			       pterange.off2 + (pa & (PAGE_SIZE - 1)) / 8,
			       1);
    //print(mmio_log, "request to install mapping %016lx -> %016lx (%016lx %016lx) %ld %ld %ld + %ld at level %d + 1\n",
    //mapped_va, mapped_pa, pa, pte, pterange.off0, pterange.off1, pterange.off2, (pa & (PAGE_SIZE - 1)) / 8, pterange.level);
    auto pa_range = mmio_pa_ranges.find_range(mapped_pa);
    if (pa_range) {
      if (mmio_va_ranges.find_range(mapped_va)) {
	//print(mmio_log, "already exists at %016lx: %016lx\n",
	//      mmio_va_ranges.find_range(mapped_va)->pa_range->pa,
	//      read64(pa));
	//write64(pa, 0);
	pa_range_pa->store_u64(pa, 0);
      } else {
	auto va_range = pa_range->virtualize(mapped_pa, mapped_va,
					     mapped_va + PAGE_SIZE);
	mmio_va_ranges.insert_range(va_range);
	if (pa_range->still_valid()) {
	  pa_range_pa->store_u64(pa, 0);
	} else {
	  print(mmio_log, "conflicting range %s, storing anyway\n", pa_range->describe().c_str());
	  pa_range_pa->store_u64(pa, 0);
	}
      }
    } else
      pa_range_pa->store_u64(pa, val);
  } else {
    //print(mmio_log, "storing non-mapping %016lx\n", (long)val);
    pa_range_pa->store_u64(pa, val);
  }
}

void
mmio_pa_range_pt::store(mmio_insn *insn, u64 pa, u128 val)
{
  if (insn->size == 16) {
    insn->size = 8;
    mmio_pa_range_pt::store(insn, pa, val & U64_MAX);
    insn->va += 8;
    mmio_pa_range_pt::store(insn, pa + 8, val >> 64);
    return;
  }
  if (insn->size != 8) {
    int size = insn->size;
    insn->size = 8;
    u128 oldval = pa_range_cache->load(insn, pa &~ 7L);
    memcpy(((char *)&oldval) + (pa & 7), &val, size);
    insn->va &= ~7L;
    mmio_pa_range_pt::store(insn, pa &~ 7L, oldval);
    return;
  }
  store_u64(pa, val);
}

class mmio_pa_range_nop
  : public mmio_pa_range
{
public:
  mmio_pa_range_nop(u64 pa, u64 pa_end);
};

mmio_pa_range_nop::mmio_pa_range_nop(u64 pa, u64 pa_end)
  : mmio_pa_range(pa, pa_end)
{
}

std::string print_val(u128 val, int size)
{
  char buf[128] = { 0, };
  switch (size) {
  case 4:
    sprintf(buf, "%08lx", (long) val);
    break;
  case 8:
    sprintf(buf, "%016lx", (long) val);
    break;
  case 16:
    sprintf(buf, "%016lx%016lx", (long) (val >> 64), (long) val);
    break;
  }

  return std::string(strdup(buf));
}

void mmio_pa_range_log::store(mmio_insn *insn, u64 pa, u128 val)
{
  //usleep(10000);
  switch (insn->size) {
#define CASE(size,str)							\
    case size:								\
      print(mmio_log,							\
	    "%016lx <- " str " {%016lx/%016lx}%s\n", pa,		\
	    (long)val, insn->elr, va_to_baseoff(insn->elr, insn->level0), \
	    lower->describe().c_str());					\
      break

    CASE(1, "%02lx");
    CASE(2, "%04lx");
    CASE(4, "%08lx");
    CASE(8, "%016lx");
#undef CASE
  default:
    print(mmio_log,
	  "%016lx <- %lx {%016lx/%016lx}%s\n", pa,
	  (long)val, insn->elr, va_to_baseoff(insn->elr, insn->level0),
	  lower->describe().c_str());
  }
  lower->store(insn, pa, val);
}
//166d3ac000
u128 mmio_pa_range_log::load(mmio_insn *insn, u64 pa)
{
  //usleep(10000);
  u128 val = lower->load(insn, pa);
  switch (insn->size) {
#define CASE(size,str)							\
    case size:								\
      print(mmio_log,							\
	    "%016lx -> " str " {%016lx/%016lx}%s\n", pa,		\
	    (long)val, insn->elr, va_to_baseoff(insn->elr, insn->level0), \
	    lower->describe().c_str());					\
      break

    CASE(1, "%02lx");
    CASE(2, "%04lx");
    CASE(4, "%08lx");
    CASE(8, "%016lx");
#undef CASE
  default:
    print(mmio_log,
	  "%016lx -> %lx {%016lx/%016lx}%s\n", pa,
	  (long)val, insn->elr, va_to_baseoff(insn->elr, insn->level0),
	  lower->describe().c_str());
  }

  return val;
}

class mmio_va_range_ignore
  : public mmio_va_range
{
  virtual bool handle_insn(mmio_insn *insn);
};

bool mmio_va_range::handle_insn(mmio_insn *insn)
{
  u32 insn32 = insn->get_insn();
  int t = (insn32 & 31);
  print(mmio_log, "handling %08x\n", insn32);
  if ((insn32 | MASK_T | MASK_N) == (0xb80047ff | MASK_T | MASK_N)) {
    int n = (insn32 >> 5) & 31;
    write_reg(insn->frame, n, read_reg(insn->frame, n, insn->level0) + 4, insn->level0);
    insn32 = 0xb8600809;
  }
  if ((insn32 | MASK_T | MASK_N) == 0xf80087ff) {
    /* 64-bit STR, post-increment */
    int n = (insn32 >> 5) & 31;
    write_reg(insn->frame, n, read_reg(insn->frame, n, insn->level0) + 8, insn->level0);
    insn32 = 0xf8200800 + t;
  }
  if ((insn32 | MASK_T | MASK_N) == (0x38001400 | MASK_T | MASK_N)) {
    /* 8-bit STRB, post-increment */
    int n = (insn32 >> 5) & 31;
    write_reg(insn->frame, n, read_reg(insn->frame, n, insn->level0) + 1, insn->level0);
    insn->size = 1;
    //print(mmio_log, "8-bit store %08x\n", insn32);
    u128 val = read_reg(insn->frame, t, insn->level0);
    store(insn, val);
    return true;
  }
  if ((insn32 & 0xffe00000) == 0x39000000) {
    /* 8-bit STRB ? */
    insn->size = 1;
    //print(mmio_log, "8-bit store %08x at %016lx\n", insn32,
    //insn->va);
    u128 val = read_reg(insn->frame, t, insn->level0);
    store(insn, val);
    return true;
  }
  if ((insn32 | MASK_T | MASK_N) == (0x38401c00 | MASK_T | MASK_N)) {
    /* 8-bit LDRB, pre-increment */
    int n = (insn32 >> 5) & 31;
    //print(mmio_log, "8-bit load %08x\n", insn32);
    write_reg(insn->frame, n, read_reg(insn->frame, n, insn->level0) + 1, insn->level0);
    insn->size = 1;
    u128 val = load(insn);
    write_reg(insn->frame, t, val, insn->level0);
    return true;
  }
  if ((insn32 & 0xffe00000) == 0x39400000) {
    /* 8-bit LDRB ? */
    //print(mmio_log, "8-bit load %08x\n", insn32);
    insn->size = 1;
    u128 val = load(insn);
    write_reg(insn->frame, t, val, insn->level0);
    return true;
  }
  if ((insn32 & 0xffe00c00) == 0xf8400000) {
    /* 32-bit LDUR (register, unsigned offset) */
    insn->size = 4;
    //print(mmio_log, "32-bit load %08x\n", insn32);
    u128 val = load(insn);
    write_reg(insn->frame, t, val, insn->level0);
    return true;
  }
  if ((insn32 & 0xffe00c00) == 0xb8600800 ||
      (insn32 & 0xffe00000) == 0xb9400000) {
    /* 32-bit LDR (register, unsigned offset) */
    insn->size = 4;
    //print(mmio_log, "32-bit load %08x\n", insn32);
    u128 val = load(insn);
    write_reg(insn->frame, t, val, insn->level0);
    return true;
  }
  if ((insn32 & 0xffe00c00) == 0xb8200800 ||
      (insn32 & 0xffe00000) == 0xb9000000) {
    /* 32-bit STR (register, unsigned offset) */
    insn->size = 4;
    //print(mmio_log, "32-bit store %08x\n", insn32);
    u128 val = read_reg(insn->frame, t, insn->level0);
    store(insn, val);
    return true;
  }
  if ((insn32 & 0xffe00c00) == 0xf8600800 ||
      (insn32 & 0xffc00000) == 0xf9400000) {
    /* 64-bit LDR (register, unsigned offset) */
    insn->size = 8;
    //print(mmio_log, "64-bit load %08x at %016lx\n", insn32,
    //  insn->va);
    u128 val = load(insn);
    write_reg(insn->frame, t, val, insn->level0);
    return true;
  }
  if ((insn32 & 0xffe00c00) == 0xf8200800 ||
      (insn32 & 0xffc00000) == 0xf9000000) {
    /* 64-bit STR (register, unsigned offset) */
    insn->size = 8;
    //print(mmio_log, "64-bit store %08x\n", insn32);
    u128 val = read_reg(insn->frame, t, insn->level0);
    store(insn, val);
    return true;
  }
  if ((insn32 & 0xffc00000) == 0xa9400000) {
    /* 128-bit LDP (register, unsigned offset) */
    //print(mmio_log, "128-bit load %08x\n", insn32);
    insn->size = 16;
    u128 val = load(insn);
    int t2 = (insn32 >> 10) & 31;
    write_reg(insn->frame, t, val&0xffffffffffffffff, insn->level0);
    write_reg(insn->frame, t2, (val >> 64), insn->level0);
    return true;
  }
  if ((insn32 & 0xffc00000) == 0xa9000000) {
    /* 128-bit STP (register, unsigned offset) */
    int t2 = (insn32 >> 10) & 31;
    //print(mmio_log, "128-bit store %08x\n", insn32);
    u64 val0 = read_reg(insn->frame, t, insn->level0);
    u64 val1 = read_reg(insn->frame, t2, insn->level0);
    u128 val = val0 + ((u128)val1 << 64);
    store(insn, val);
    return true;
  }
  print(mmio_log, "unhandled insn %08x {%016lx / %016lx}\n", insn32,
	insn->elr, va_to_baseoff(insn->elr, insn->level0));
  sleep(1);
  return false;
}

bool simulate_insn(unsigned long frame, unsigned insn,
		   unsigned long elr, unsigned long va,
		   unsigned long pa, unsigned long level0,
		   unsigned long action)
{
  pa &= ~0x3fffL;
  pa |= (va & 0x3fffL);

  int t = insn & 31;
  static unsigned v23d2b000c = 0;
  print(mmio_log, "handling insn %08lx at pa %016lx\n", insn, pa);
  if ((insn & 0xffe00c00) == 0xb8600800 ||
      (insn & 0xffe00000) == 0xb9400000) {
    /* 32-bit LDR (register, unsigned offset) */
    if (pa == 0x23b100000 + 0x2000 ||
	pa == 0x23b100000 + 0x2004) {
      //print("[handled] interrupt %016lx %d\n", pa, t);
      write64(ppage + 0x3fb8, 0xfffffff000004000 + (pa & 0x3fff));
      write64(ppage + 0x3fb0, frame + t * 8);
      //write64(ppage + 0x3ff8, elr + 4);
      install_page(0xfffffff000004000,
		   0x23b100000, 2, read64(ppage + 0x3fe8));
      //install_page2(0xfffffff000004000,
      //	    0x23b100000, 3, read64(ppage + 0x3fe0));
      print(mmio_log, "triggering interrupt event with address %016lx [%016lx/%016lx] -> x%d\n",
	    (pa & 0x3fff), read64(ppage + 0x3fb8),read64(ppage + 0x3fb0), t);
      print(mmio_log, "TTBR %016lx %016lx %016lx frame %016lx\n",
	    read64(ppage + 0x3fe8), read64(ppage + 0x3fe0), read64(ppage + 0x3e08), frame);
      return false;
    } else if ((pa & ~0x3fffL) == 0x23b100000) {
      print(mmio_log, "[unhandled?]interrupt %016lx!\n", pa);
    } else {
      u64 val = action ? read32(pa) : 0;
      //if (pa == 0x23d2b000c)
      //val = read32(pa);
      print(mmio_log, "%016lx -> %08lx {%016lx / %016lx}%s\n", pa, val, elr, va_to_baseoff(elr, level0), action ? "" : "[ignored]");
      write_reg(frame, t, val, level0);
      return true;
    }
  }
  if ((pa & 0xffffffffffffc000) == 0x23b100000) {
    print(mmio_log, "[unhandled]interrupt %016lx!\n", pa);
    return false;
  }
  if ((insn & 0xffe00c00) == 0xb8200800 ||
      (insn & 0xffe00000) == 0xb9000000) {
    /* 32-bit STR (register, unsigned offset) */
    u32 val;
    print(mmio_log, "%016lx <- %08lx {%016lx / %016lx}%s\n", pa, read_reg(frame, t, level0),
	  elr, va_to_baseoff(elr, level0),
	  action ? "" : " [ignored]");
    if (pa == 0x23d2b000c)
      val = read_reg(frame, t, level0)  & ~1L;
    else
      val = read_reg(frame, t, level0);
    if (action)
      write32(pa, val);
    return true;
  }
  if ((insn & 0xffe00c00) == 0xf8200800 ||
      (insn & 0xffc00000) == 0xf9000000) {
    /* 64-bit STR (register, unsigned offset) */
    print(mmio_log, "%016lx <- %016lx {%016lx / %016lx}%s\n", pa, read_reg(frame, t, level0),
	  elr, va_to_baseoff(elr, level0),
	  action ? "" : " [ignored]");
    if (action)
      write64(pa, read_reg(frame, t, level0));
    return true;
  }
  if ((insn & 0xffe00c00) == 0xf8600800 ||
      (insn & 0xffc00000) == 0xf9400000) {
    /* 64-bit LDR (register, unsigned offset) */
    u64 val = action ? read64(pa) : 0;
    //if (pa == 0x210040090)
    //  val = (elr + 4) &~ 0xfffe000000000000;
    print(mmio_log, "%016lx -> %016lx {%016lx / %016lx}%s\n", pa, val,
	  elr, va_to_baseoff(elr, level0),
	  action ? "" : "[ignored]");
    write_reg(frame, t, val, level0);
    return true;
  }
  if ((insn & 0xffc00000) == 0xa9400000) {
    /* 128-bit LDP (register, unsigned offset) */
    u64 val0 = action ? read64(pa) : 0;
    u64 val1 = action ? read64(pa + 8) : 0;
    int t2 = (insn >> 10) & 31;
    print(mmio_log, "%016lx -> %016lx%016lx {%016lx / %016lx}%s\n", pa, val0, val1,
	  elr, va_to_baseoff(elr, level0),
	  action ? "" : "[ignored]");
    write_reg(frame, t, val0, level0);
    write_reg(frame, t2, val1, level0);
    return true;
  }
  if ((insn & 0xffc00000) == 0xa9000000) {
    /* 128-bit STP (register, unsigned offset) */
    int t2 = (insn >> 10) & 31;
    u64 val0 = read_reg(frame, t, level0);
    u64 val1 = read_reg(frame, t2, level0);
    print(mmio_log, "%016lx <- %016lx%016lx {%016lx / %016lx}%s\n", pa, val0, val1,
	  elr, va_to_baseoff(elr, level0),
	  action ? "" : " [ignored]");
    if (action) {
      write64(pa, val0);
      write64(pa + 8, val1);
    }
    return true;
  }
  print(mmio_log, "unhandled insn %08x {%016lx / %016lx}\n", insn,
	elr, va_to_baseoff(elr, level0));
  return false;
  if ((insn & 0xffe00c00) == 0xb8000400) { /* STR (post-index) */
    write32(pa, read_reg(frame, t, level0));
  } else if ((insn & 0xffe00c00) == 0xb8000c00) { /* STR (pre-index) */
    write32(pa, read_reg(frame, t, level0));
  } else if ((insn & 0xffe00000) == 0xb9000000) { /* STR (unsigned offset) */
    write32(pa, read_reg(frame, t, level0));
  } else if ((insn & 0xffe00c00) == 0xf8000400) { /* STR (post-index) */
    write64(pa, read_reg(frame, t, level0));
  } else if ((insn & 0xffe00c00) == 0xf8000c00) { /* STR (pre-index) */
    write64(pa, read_reg(frame, t, level0));
  } else if ((insn & 0xffe00000) == 0xf9000000) { /* STR (unsigned offset) */
    write64(pa, read_reg(frame, t, level0));
  } else if ((insn & 0xffe00c00) == 0xf8200800) { /* STR (register) */
    write64(pa, read_reg(frame, t, level0));
  } else if ((insn & 0xffe00c00) == 0xf8600800) { /* LDR (register) */
    write_reg(frame, t, read64(pa), level0);
  } else if ((insn & 0xffe00c00) == 0xf8400400) { /* LDR (post-index) */
    write_reg(frame, t, read64(pa), level0);
  } else if ((insn & 0xffe00c00) == 0xf8400c00) { /* LDR (pre-index) */
    write_reg(frame, t, read64(pa), level0);
  } else if ((insn & 0xffe00000) == 0xf9400000) { /* LDR (unsigned offset) */
    write_reg(frame, t, read64(pa), level0);
  } else if ((insn & 0xffe00c00) == 0xb8600800) { /* LDR (register) */
    write_reg(frame, t, read32(pa), level0);
  } else if ((insn & 0xffe00c00) == 0xb8400400) { /* LDR (post-index) */
    write_reg(frame, t, read32(pa), level0);
  } else if ((insn & 0xffe00c00) == 0xb8400c00) { /* LDR (pre-index) */
    write_reg(frame, t, read32(pa), level0);
  } else if ((insn & 0xffe00000) == 0xb9400000) { /* LDR (unsigned offset) */
    write_reg(frame, t, read32(pa), level0);
  } else if ((insn & 0xff000000) == -1) {
    if ((insn & 0xff000000) == -1) {
      /* 32-bit load */
    } else if ((insn & 0xff000000) == -1) {
      /* 64-bit load */
    }
  } else {
    return false;
  }

  return true;
}

void unmap_pa_range(u64 addr, u64 addr2)
{
}

static u64 copypage(u64 addr)
{
  u64 ret = alloc_page();
  for (int i = 0; i < 2048; i++)
    write64(ret + 8 * i, addr + 8 * i);
  return ret;
}

static void unmap_range(u64 pt, u64 va, u64 va_end)
{
}

static std::vector<mmio_pterange> pt_ranges(u64 pt)
{
  std::vector<mmio_pterange> ret;
  u64 ttbr = pt;

  mmio_pterange p(pt);
  p.ttbr = pt;
  p.pa0 = 0;
  p.pt0 = pt;
  p.va0 = offs_to_va(0, 0, 0, 1);
  p.ptep = 0;
  p.pte = 0;
  p.level = 0;
  p.off0 = p.off1 = p.off2 = 0;
  ret.push_back(p);

  for (unsigned long off0 = 0; off0 < 2048; off0++) {
    u64 pte1 = read64(pt + 8 * off0);
    u64 level1 = pte1 & PAGE_TABLE_PAGE_MASK;
    if ((pte1 & 3) == 3) {
      mmio_pterange p(level1);
      p.ttbr = ttbr;
      p.pa0 = 0;
      p.pt0 = level1;
      p.va0 = offs_to_va(off0, 0, 0, 1);
      p.ptep = pt + 8 * off0;
      p.pte = pte1;

      p.level = 1;
      p.off0 = off0;
      p.off1 = 0;
      p.off2 = 0;

      ret.push_back(p);
      for (unsigned long off1 = 0; off1 < 2048; off1++) {
	u64 pte2 = read64(level1 + 8 * off1);
	u64 level2 = pte2 & PAGE_TABLE_PAGE_MASK;
	if ((pte2 & 3) == 3) {
	  {
	    mmio_pterange p(level2);
	    p.ttbr = ttbr;
	    p.pa0 = 0;
	    p.pt0 = level2;
	    p.va0 = offs_to_va(off0, off1, 0, 1);
	    p.ptep = level1 + 8 * off1;
	    p.pte = pte2;
	    p.level = 2;
	    p.off0 = off0;
	    p.off1 = off1;
	    p.off2 = 0;

	    ret.push_back(p);
	  }
	  for (unsigned long off2 = 0; off2 < 2048; off2++) {
	    u64 pte3 = read64(level2 + 8 * off2);
	    u64 page = pte3 & PAGE_TABLE_PAGE_MASK;
	    u64 va = offs_to_va(off0, off1, off2, 1);
	    if (pte3 & 1) {
	      mmio_pterange p(level1);
	      p.ttbr = ttbr;
	      p.pa0 = page;
	      p.pt0 = 0;
	      p.va0 = va;
	      p.ptep = level2 + 8 * off2;
	      p.pte = pte3;

	      p.level = 3;
	      p.off0 = off0;
	      p.off1 = off1;
	      p.off2 = off2;

	      ret.push_back(p);
	    }
	  }
	} else if (pte2 & 1) {
	  mmio_pterange p(level2);
	  p.ttbr = ttbr;
	  p.pa0 = level2;
	  p.pt0 = 0;
	  p.va0 = offs_to_va(off0, off1, 0, 1);
	  p.ptep = level1 + 8 * off1;
	  p.pte = pte2;

	  p.level = 2;
	  p.off0 = off0;
	  p.off1 = off1;
	  p.off2 = 0;

	  ret.push_back(p);
	}
      }
    }
  }

  return ret;
}

void
verbose_translation(u64 va, u64 pt)
{
  fprintf(stderr, "translating %016lx using %016lx pt\n",
	  va, pt);
  for (auto p : pt_ranges(pt)) {
    if (p.va0 <= va && va < p.va0 + p.size())
      fprintf(stderr, "matching range %s\n",
	      p.describe().c_str());
  }
}


static void steal_page_table(u64 pt)
{
  auto ranges = pt_ranges(pt);
  std::multimap<u64,std::pair<u64,u64>> pt_vas;
  std::multimap<u64,mmio_pterange> pts;
  bool didsomething = true;
  mmio_pterange pterange(pt);
  pterange.ttbr = pt;
  pterange.level = 0;
  pterange.off0 = pterange.off1 = pterange.off2 = 0;
  pterange.pa0 = 0;
  pterange.va0 = offs_to_va(0, 0, 0, 1);
  pterange.pt0 = pt;
  pts.insert(std::make_pair(pt, pterange));
  while (didsomething) {
    didsomething = false;
    for (unsigned long off0 = 0; off0 < 2048; off0++) {
      u64 pte1 = read64(pt + 8 * off0);
      u64 level1 = pte1 & PAGE_TABLE_PAGE_MASK;
      if (pte1 & 1)
	if (!pts.count(level1)) {
	  didsomething = true;
	  mmio_pterange pterange(level1);
	  pterange.ttbr = pt;
	  pterange.level = 1;
	  pterange.off0 = off0;
	  pterange.off1 = 0;
	  pterange.off2 = 0;
	  pterange.pa0 = level1;
	  pterange.va0 = offs_to_va(off0, 0, 0, 1);
	  pterange.pt0 = 0;
	  pts.insert(std::make_pair(level1, pterange));
	}
      if ((pte1 & 3) == 3) {
	for (unsigned long off1 = 0; off1 < 2048; off1++) {
	  u64 pte2 = read64(level1 + 8 * off1);
	  u64 level2 = pte2 & PAGE_TABLE_PAGE_MASK;
	  if (pte2 & 1)
	    if (!pts.count(level2)) {
	      mmio_pterange pterange(level2);
	      pterange.ttbr = pt;
	      pterange.level = 2;
	      pterange.off0 = off0;
	      pterange.off1 = off1;
	      pterange.off2 = 0;
	      pterange.pa0 = level2;
	      pterange.va0 = offs_to_va(off0, off1, 0, 1);
	      pterange.pt0 = 0;
	      didsomething = true;
	      pts.insert(std::make_pair(level2, pterange));
	    }
	  if ((pte2 & 3) == 3) {
	  } else if ((pte2 & 3) == 1) {
	    print(mmio_log, "found large block %016lx-%016lx at %016lx %016lx\n",
		  level2 + (1 << (14 + 11)),
		  pte2, pt + 8 * off0, level1 + 8 * off1);
	  }
	}
      } else if ((pte1 & 3) == 1) {
	print(mmio_log, "found huge block %016lx at %016lx\n",
	      pte1, pt + 8 * off0);
      }
    }
  }
  for (auto pterange : ranges) {
    for (auto page : pterange.pages()) {
      auto rangerange = pts.equal_range(page);
      for (auto it = rangerange.first; it != rangerange.second; it++) {
	auto pa_range =
	  new mmio_pa_range_log
	  (new mmio_pa_range_pt(page, page + 0x4000,
				it->second));
	mmio_pa_ranges.insert_range(pa_range);
      }
    }
    if (pterange.pt0) {
      auto pa_range =
	new mmio_pa_range_log
	(new mmio_pa_range_pt(pterange.pt0,
			      pterange.pt0 + PAGE_SIZE,
			      pterange));
      mmio_pa_ranges.insert_range(pa_range);
    }
  }
  unsigned long unmapped = 0;
  for (auto pte : ranges) {
    if (pts.count(pte.pa0)) {
      auto pa_range = mmio_pa_ranges.find_range(pte.pa0);
      if (!pa_range)
	print(mmio_log, "could not find pa range %016lx\n", pte.pa0);
      u64 size = PAGE_SIZE;
      if (pte.level < 3)
	size <<= 11;
      if (pte.level < 2)
	size <<= 11;
      auto va_range = pa_range->virtualize(pte.pa0, pte.va0, pte.va0 + size);
      mmio_va_ranges.insert_range(va_range);
      //print(mmio_log, "va_range %016lx/%016lx\n", va_range->va, pte.va0);
      //write64(pte.ptep, read64(pte.ptep) & ~0x0060000000000000L);
      write64(pte.ptep, 0);
      unmapped++;
    }
  }
  print(mmio_log, "found %ld page table pages, unmapped %ld, now have %ld mappings\n", pts.size(), unmapped, mmio_pa_ranges.size());
  sleep(3);
}

static void dump_page_table(u64 pt0, int high = 1)
{
  for (auto p : pt_ranges(pt0)) {
    fprintf(stderr, "%016lx %016lx %016lx %016lx %016lx %016lx %d\n",
	    p.ttbr, pt0, p.pte, p.pa0, p.pt0, p.va0, p.level);
    static int count;
    if (count++ % 32 == 0)
      sleep(3);
  }
}

static void dump_page_table_for_va(u64 pt0, u64 va, int high = 1)
{
  for (auto p : pt_ranges(pt0)) {
    if (p.va0 <= (va + (1 << (14 + 11))) && va - ((1L << (14+11)) - 1) < p.va0 + p.size()) {
      fprintf(stderr, "%016lx %016lx %016lx %016lx %016lx %016lx %d\n",
	      p.ttbr, pt0, p.pte, p.pa0, p.pt0, p.va0, p.level);
      static int count;
      if (count++ % 32 == 0)
	sleep(3);
    }
  }
}

static unsigned long base;
static void do_handle_mmio()
{
  {
    u64 pt4 = base + 0x3a84000;
    install_page(0xfffffff000004000, 0x23b100000, PAGE_RW, pt4);
    install_page(0xfffffff000000000, 0xb90000000, PAGE_RW, pt4);
    install_page(0xfffffff100000000, 0x23b100000, PAGE_RW, pt4);
    install_page(0xfffffff100008000, 0x23d2b0000, PAGE_RW, pt4);
    install_page(0xfffffff800000000, 0xb90000000, 1, pt4);
    install_page(0xfffffff800004000, 0xb90004000, 4, pt4);
  }
  //dump_page_table(base + 0x3a84000);
  //dump_page_table(base + 0x3a80000);
  if (read64(ppage + 0x3f08) != 0x141ef) {
    steal_page_table(read64(ppage + 0x3fe8));
    write64(ppage + 0x3f08, 0x141ef);
  }
  u64 success = 0;
  u64 esr = read64(ppage + 0x3fd8);
  u64 elr = read64(ppage + 0x3ff8);
  //print(mmio_log, "esr %016lx\n", esr);
  if ((esr & 0xe8000000UL) != 0x80000000UL) {
    write64(ppage + 0x3fd0, success);
    asm volatile("dmb sy" : : : "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    write64(ppage + 0x3ff0, 0);
    return;
  }
  u64 va_reg = read64(ppage + 0x3fb0);
  if (va_reg) {
    print(mmio_log, "interrupt event (unknown)%s\n", "");
    asm volatile("dmb sy" ::: "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    asm volatile("dmb sy" ::: "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    //while (read64(ppage + 0x3fb0));
    asm volatile("dmb sy" ::: "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    u64 event = read64(ppage + 0x3fb8);
    write64(ppage + 0x3fb0, 0);
    write64(ppage + 0x3ff0, 0);
    print(mmio_log, "interrupt event %08lx\n", event);
    //write64_to_va(va, event, read64(ppage + 0x3fe8));
    return;
  }
  u64 far = read64(ppage + 0x3ff0);
  mmio_va_range *range = mmio_va_ranges.find_range(far);

  if (!range) {
    u64 frame = read64(ppage + 0x3fc8);
    print(mmio_log, "unknown far %016lx esr %016lx elr %016lx frame %016lx\n", far, esr,
	  elr, frame);
    for (int i = 0; i < 32; i++)
      print(mmio_log, "reg%02d: %016lx\n",
	    i, read64_at_va(frame + 8 * i, read64(ppage + 0x3fe8)));
    //steal_page_table(read64(ppage + 0x3fe8));
    for (auto pterange : pt_ranges(read64(ppage + 0x3fe8))) {
      if (pterange.va0 == (far & ~(PAGE_SIZE - 1))) {
	print(mmio_log, "but we know about it!\n%s", "");
	success = (esr != 0x9600004f);
      }
      for (auto page : pterange.pages()) {
	if (page == (far & ~(PAGE_SIZE - 1))) {
	  print(mmio_log, "but we know about it2!\n%s", "");
	  success = (esr != 0x9600004f);
	}
      }
    }
    write64(ppage + 0x3fd0, success);
    asm volatile("dmb sy" : : : "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    write64(ppage + 0x3ff0, 0);
    return;
  }

  mmio_insn insn;
  insn.va = far;
  insn.elr = elr;
  insn.level0 = read64(ppage + 0x3fe8);
  insn.frame = read64(ppage + 0x3fc8);
  insn.size = 0;

  if (insn.elr == insn.va) { /* not perfect */
    print(mmio_log, "insn fetch at %016lx %s\n",
	  insn.va, range->describe().c_str());
    range->force_remap();
    success = false;
  } else {
    success = range->handle_insn(&insn);
    if (success) {
      write64(ppage + 0x3ff8, elr + 4);
    }
  }

  //print(mmio_log, "success: %d\n", success);
  write64(ppage + 0x3fd0, success);
  asm volatile("dmb sy" : : : "memory");
  asm volatile("dsb sy");
  asm volatile("isb");
  write64(ppage + 0x3ff0, 0);
  return;
}

static void handle_mmio()
{
  print(mmio_log, "handling mmio %016lx %016lx\n",
  	read64(ppage + 0x3fa0), read64(ppage + 0x3fa8));
  do_handle_mmio();
  print(mmio_log, "handled mmio! success %d\n", read64(ppage+0x3fd0));
}


bool sometimes()
{
  static time_t last_time;
  time_t this_time = time(NULL);
  if (this_time - last_time > 30) {
    last_time = this_time;
    return true;
  }
  return false;
}

void mainloop()
{
  if (read64(ppage + 0x3ff0) != 0) {
    handle_mmio();
  }
  if (sometimes()) {
    for (unsigned long off = 0x800000000; off < 0x980000000; off += PAGE_SIZE){
      if (read64(off) == 0xd547fdfeceade631) {
	fprintf(stderr, "read %016lx %016lx %016lx\n",
		off, read64(off + 8), read64(off + 16));
      }
    }
  }
}

static void start_mmio()
{
  write64(ppage + 0x3fb0, 0);
  write64(ppage + 0x3e00, 0xffffffff);
}

static void sigbus_sigaction(int signal, siginfo_t *, void *ucontext_v)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  fprintf(stderr, "[%16ld.%06ld] SIGBUS %d!\n", (long)tv.tv_sec, (long)tv.tv_usec, signal);
  ucontext_t *ucontext = (ucontext_t *)ucontext_v;
  sleep(1);
  global_sigbus_flag = 1;
  ucontext->uc_mcontext.pc += 4;
  setcontext(ucontext);
}

int main(int argc, char **argv)
{
  mmio_log = fopen("/mmio-log", "a");
  if (!mmio_log)
    mmio_log = stdout;

  pt_log = fopen("/pt-log", "a");
  if (!pt_log)
    pt_log = stdout;

  if (argv[1] && strcmp(argv[1], "init") == 0) {
    printf("reading base...\n");
    unsigned long base = read64(0xac0000008);
    write64(0xb90003e88, 0);
    sleep(15);
    printf("base at %016lx\n", base);
    unsigned saved_code[4][16];
    printf("patching code...\n");
    for (int i = 0; i < 16; i++)
      saved_code[1][i] = read32(base + 0xc0d8a0 + i * 4);
    //write32(base + 0x363ea50, 0xd503201f);
    //for (int i = 0; i < ARRAYELTS(wait_for_confirmation); i++)
    //  write32(base + 0xd57378 + i * 4, wait_for_confirmation[i]);
    //for (int i = 0; i < ARRAYELTS(infloop); i++)
    //  write32(base + 0xc0d8a0 + i * 4, infloop[i]);
    //for (int i = 0; i < ARRAYELTS(delay_loop); i++)
    //  write32(base + 0xc62340 + i * 4, delay_loop[i]);
    //for (int i = 0; i < ARRAYELTS(optimized_putc); i++)
    //  write32(base + 0xd3d58c + i * 4, optimized_putc[i]);
    printf("done patching, starting wait...\n");
    static int count = 2049;
    //write32(0x210030fb0, 0xc5acce55);
    write64(0xb90003e08, 0);
    write64(0xb90003e00, 1);
    write64(0xb90003e08, base + 0x3adc000);
    //write32(0x210030fb0, 0xc5acce55);
    write64(0xb90003e10, 0xb90010000);
    printf("TTBR at %016lx\n", read64(0xb90003e08));
    //printf("TTBR at %016lx\n", read64(base + 0x49f4018));
    install_page(0xfffffff000004000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff000000000, 0xb90000000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff100000000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff100008000, 0x23d2b0000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff800000000, 0xb90000000, 1, read64(0xb90003e08));
    install_page(0xfffffff800004000, 0xb90004000, 1, read64(0xb90003e08));
    printf("page table 1\n");
    dump_pt_compressed(read64(0xb90003e08));
    printf("page table 2\n");
    dump_pt_compressed(base + 0x806b98000 - 0x8030bc000);
    printf("page table 3\n");
    dump_pt(base + 0x806b94000 - 0x8030bc000);
    //install_page2(0x0001fff800004000, 0xb90004000, 1, read64(base + 0x3ad66e8));
    install_page(0xfffffff000004000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff000000000, 0xb90000000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff100000000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff100008000, 0x23d2b0000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff800000000, 0xb90000000, 1, read64(0xb90003e08));
    install_page(0xfffffff800004000, 0xb90004000, 1, read64(0xb90003e08));

    //write32(0xc0d8a4,  0xd42c8e40);
    u64 pt4 = base + 0x3a84000;
    printf("page table 4\n");
    dump_pt_compressed(pt4);
    install_page(0xfffffff000004000, 0x23b100000, PAGE_RW, pt4);
    install_page(0xfffffff000000000, 0xb90000000, PAGE_RW, pt4);
    install_page(0xfffffff100000000, 0x23b100000, PAGE_RW, pt4);
    install_page(0xfffffff100008000, 0x23d2b0000, PAGE_RW, pt4);
    install_page(0xfffffff800000000, 0xb90000000, 1, pt4);
    install_page(0xfffffff800004000, 0xb90004000, 4, pt4);

    {
      int i = 0;
#define code4 new_irq_handler_part1
      /* code4 should be injector-page.S.elf.bin */
      while (i < ARRAYELTS(code4)) {
	write32(0xb90000000 + i * 4, code4[i]);
	i++;
      }
#define code5 new_irq_handler_part2
      /* code5 should be mmiotrace.c.S.elf.bin */
      while (i < ARRAYELTS(code5) + ARRAYELTS(code4)) {
	write32(0xb90000000 + i * 4, code5[i - ARRAYELTS(code4)]);
	i++;
      }
    }
    {
      int i = 0;
#define code4 wait_for_confirmation_receiver
      while (i < ARRAYELTS(code4)) {
	write32(0xb90004000 + i * 4, code4[i]);
	i++;
      }
#define code5 wait_for_confirmation_receiver_part2
      while (i < ARRAYELTS(code5) + ARRAYELTS(code4)) {
	write32(0xb90004000 + i * 4, code5[i - ARRAYELTS(code4)]);
	i++;
      }
    }
    unsigned long offs[] = {
      0, /* 0x80, */
      0x200,
      0x400,
      0x8000 - 0x2000, 0x8200 - 0x2000, 0x8400 - 0x2000,
      0x9000 - 0x2000, 0x9200 - 0x2000, 0x9400 - 0x2000,
      0x13ec000 - 0xc02000,
      0x13ec200 - 0xc02000,
      0x13ec400 - 0xc02000,
      0x13ec080 - 0xc02000, 0x13ec280 - 0xc02000, 0x13ec480 - 0xc02000,
      0x13ec100 - 0xc02000, 0x13ec300 - 0xc02000, 0x13ec500 - 0xc02000,
      0x13ec180 - 0xc02000, 0x13ec380 - 0xc02000, 0x13ec580 - 0xc02000,
    };
    for (int j = 0; j < ARRAYELTS(offs); j++) {
      unsigned long off = offs[j];
      unsigned oldbr = read32(base + 0xc02000 + off);
      if (off < 0x13ec000 - 0xc02000) {
	for (int i = 0; i < ARRAYELTS(new_vbar_entry); i++) {
	  write32(base + 0xc02000 + off + 4 * i, new_vbar_entry[i]);
	}
      } else {
	for (int i = 0; i < ARRAYELTS(new_vbar_entry_special); i++) {
	  write32(base + 0xc02000 + off + 4 * i, new_vbar_entry_special[i]);
	}
      }
      if ((oldbr & 0xff000000) == 0x14000000)
	write32(base + 0xc02000 + off + 0x4, oldbr - 1);
      else
	write32(base + 0xc02000 + off + 0x4, oldbr);
    }
    write64(ppage + 0x3f00, 1);
    //system("pt unmap-pa 0x23d2b0000 0x23d2b4000 0");
    asm volatile("isb");
    write64(0xb90003e88, 1);
    sleep(20);
    write64(0xb90003e08, read64(base + 0x3ad66f0));
    write64(0xb90003e08, read64(base + 0x3ad66f0));
    install_page(0xfffffff000004000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff000000000, 0xb90000000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff100000000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff100008000, 0x23d2b0000, PAGE_RW, read64(0xb90003e08));
    install_page(0xfffffff800000000, 0xb90000000, 1, read64(0xb90003e08));
    install_page(0xfffffff800004000, 0xb90004000, 1, read64(0xb90003e08));
    {
      printf("page table 1[3]: %016lx\n", read64(0xb90003e08));;
      dump_pt_compressed(read64(0xb90003e08));
      printf("page table 2[3]: %016lx\n", 0x806b98000 - 0x8030bc000);
      install_page(0xfffffff000004000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
      install_page(0xfffffff000000000, 0xb90000000, PAGE_RW, read64(0xb90003e08));
      install_page(0xfffffff100000000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
      install_page(0xfffffff100008000, 0x23d2b0000, PAGE_RW, read64(0xb90003e08));
      install_page(0xfffffff800000000, 0xb90000000, 1, read64(0xb90003e08));
      install_page(0xfffffff800004000, 0xb90004000, 1, read64(0xb90003e08));
      dump_pt_compressed(base + 0x806b98000 - 0x8030bc000);
      printf("page table 3[3]: %016lx\n", base + 0x806b94000 - 0x8030bc000);
      dump_pt(base + 0x806b94000 - 0x8030bc000);
      //install_page2(0x0001fff800004000, 0xb90004000, 1, read64(base + 0x3ad66e8));
      install_page(0xfffffff000004000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
      install_page(0xfffffff000000000, 0xb90000000, PAGE_RW, read64(0xb90003e08));
      install_page(0xfffffff100000000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
      install_page(0xfffffff100008000, 0x23d2b0000, PAGE_RW, read64(0xb90003e08));
      install_page(0xfffffff800000000, 0xb90000000, 1, read64(0xb90003e08));
      install_page(0xfffffff800004000, 0xb90004000, 1, read64(0xb90003e08));

      write32(0xc0d8a4,  0xd42c8e40);
      u64 pt4 = base + 0x3a84000;
      printf("page table 4[3]: %016lx\n", pt4);
      dump_pt_compressed(pt4);
      //install_page(0xfffffff200004000, 0x23b100000, PAGE_RW, pt4);
      //install_page(0xfffffff200000000, 0xb90000000, PAGE_RW, pt4);
      //install_page(0xfffffff300000000, 0x23b100000, PAGE_RW, pt4);
      //install_page(0xfffffff300008000, 0x23d2b0000, PAGE_RW, pt4);
      ////install_page(0xfffffffa00000000, 0xb90000000, 1, pt4);
      //install_page(0xfffffffa00004000, 0xb90004000, 4, pt4);
      //system("pt unmap-pa 0x23b204000 0x23b208000 0");
      //system("pt unmap-pa 0x200100000 0x200200000 0");
      //system("pt unmap-pa 0x23fe50000 0x23ff00000 0");
      //for (int i = 1; i < ARRAYELTS(infloop); i++)
      //  write32(base + 0xc0d8a0 + i * 4, saved_code[1][i]);
      //write32(base + 0xc0d8a0, saved_code[1][0]);
    }
    {
      u64 pt4 = base + 0x3a84000;
      printf("page table 4\n");
      dump_pt_compressed(pt4);
    }
    sleep(5);
    for (int j = 0; j < ARRAYELTS(offs); j++) {
      unsigned long off = offs[j];
      write32(base + 0xc02000 + off + 0x38, off + 0xc02000);
    }

    printf("done\n");
    exit(0);
  }
  base = read64(0xac0000008);
  mmio_pa_ranges.insert_range
    (new mmio_pa_range_log
     (new mmio_pa_range_nop(0x23d2b0000, 0x23d2c0000)));
  mmio_pa_ranges.insert_range
    (new mmio_pa_range_log
     (new mmio_pa_range_pa(0x200000000, 0x23b000000)));
  mmio_pa_ranges.insert_range
    (new mmio_pa_range_log
     (new mmio_pa_range_pa(0x23b200000, 0x300000000)));
  mmio_pa_ranges.insert_range
    (/* new mmio_pa_range_log */
     (new mmio_pa_range_pa(0xbdf438000, 0xbe03d8000)));

  start_mmio();

  static struct sigaction sigbus_action;
  sigbus_action.sa_sigaction = sigbus_sigaction;
  sigbus_action.sa_flags = SA_SIGINFO;
  sigaction(SIGBUS, &sigbus_action, NULL);
  sigaction(SIGSEGV, &sigbus_action, NULL);

  while (true)
    mainloop();
  return 0;
}
