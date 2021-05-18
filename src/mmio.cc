#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sched.h>
#include <sys/time.h>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <unordered_map>

#include "ptstuff.h"

#define MAGIC_WORD 0x140008b6b5fffff8

static FILE *log;
static FILE *pt_log;
static FILE *mmio_log;

#define print(log, fmt, ...) do {					\
    struct timeval tv;							\
    gettimeofday(&tv, NULL);						\
    fprintf(log, "[%16ld.%06ld] " fmt, (long)tv.tv_sec, (long)tv.tv_usec, __VA_ARGS__); \
    fflush(log);							\
    fprintf(stderr, "[%16ld.%06ld] " fmt, (long)tv.tv_sec, (long)tv.tv_usec, __VA_ARGS__); \
    usleep(0);								\
  } while (0)

typedef unsigned __int128 u128;

class mmio_pterange {
public:
  u64 pa0;
  u64 va0;
  u64 ptep;
  u64 pte;

  int level;
  unsigned long off0;
  unsigned long off1;
  unsigned long off2;

  std::vector<u64> pages()
  {
    std::vector<u64> ret;
    u64 size = 1;
    if (level == 2)
      size = 1 << 11;
    if (level == 1)
      size = 1 << 22;
    for (u64 pa = pa0; pa < pa0 + size * 0x4000; pa += 0x4000)
      ret.push_back(pa);

    return ret;
  }
};

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
  u64 pa;
  u64 pa_end;

  mmio_pa_range(u64 pa, u64 pa_end)
    : pa(pa), pa_end(pa_end)
  {
  }

  mmio_pa_range()
    : pa(0), pa_end(0)
  {
  }

  virtual void store(mmio_insn *insn, u64 pa, u128 val);
  virtual u128 load(mmio_insn *insn, u64 pa);
  virtual mmio_va_range *virtualize(u64 pa, u64 va, u64 va_end);
};

class mmio_pa_range_pa
  : public mmio_pa_range {
public:
  virtual void store(mmio_insn *insn, u64 pa, u128 val);
  virtual u128 load(mmio_insn *insn, u64 pa);

  mmio_pa_range_pa(u64 pa, u64 pa_end)
    : mmio_pa_range(pa, pa_end) {}
};

class mmio_pa_range_cache
  : public mmio_pa_range {
public:
  u64 *buf;

  mmio_pa_range_cache(u64 pa, u64 pa_end)
    : buf(new u64[(pa_end - pa) / 8])
  {
    for (int i = 0; i < (pa_end - pa) / 8; i++)
      buf[i] = read64(pa + 8 * i);
  }

  virtual void store(mmio_insn *insn, u64 pa, u128 val);
  virtual u128 load(mmio_insn *insn, u64 pa);
};

#define U64_MAX 0xffffffffffffffff

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
    abort();
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
    abort();
  }
}

class mmio_pa_range_pt
  : public mmio_pa_range {
public:
  mmio_pterange pterange;
  mmio_pa_range_pa *pa_range_pa;
  mmio_pa_range_cache *pa_range_cache;

  virtual void store(mmio_insn *insn, u64 pa, u128 val);
  virtual u128 load(mmio_insn *insn, u64 pa);

  mmio_pa_range_pt(u64 pa, u64 pa_end)
    : mmio_pa_range(pa, pa_end), pa_range_pa(new mmio_pa_range_pa(pa, pa_end)),
      pa_range_cache(new mmio_pa_range_cache(pa, pa_end))
  {
  }

  mmio_pa_range_pt(u64 pa, u64 pa_end, mmio_pterange pterange)
    : mmio_pa_range(pa, pa_end), pa_range_pa(new mmio_pa_range_pa(pa, pa_end)),
      pa_range_cache(new mmio_pa_range_cache(pa, pa_end)), pterange(pterange)
  {
  }
};

#define PAGE_TABLE_PAGE_MASK (0xfffffff000UL)

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

  virtual std::string get_name()
  {
    return "unknown";
  }

  virtual std::string note()
  {
    return "";
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

  void insn_side_effects(unsigned long frame, unsigned insn,
			 unsigned long level0);
  bool handle_insn(mmio_insn *insn);

  virtual mmio_va_range *virtualize(u64 oldva, u64 newva, u64 newva_end)
  {
    return new mmio_va_range(pa_range, 0, newva, newva_end);
  }
};

class mmio_va_range_pa
  : public mmio_va_range {
public:
  u64 pa;

  virtual mmio_va_range *virtualize(u64 pa, u64 va, u64 va_end)
  {
    auto ret = new mmio_va_range_pa(pa_range, pa - this->pa,
				    pa + (va - this->va),
				    pa + (va_end - this->va));
    ret->va = va;
    ret->va_end = va_end;

    return ret;
  }
  mmio_va_range_pa(mmio_pa_range *pa_range, u64 pa_off, u64 pa, u64 pa_end)
    : pa(pa), mmio_va_range(pa_range, pa_off, pa, pa_end) {}
  mmio_va_range_pa(mmio_pa_range *pa_range)
    : pa(pa_range->pa), mmio_va_range(pa_range, 0, pa_range->pa, pa_range->pa_end) {}
};

class mmio_pa_table
  : public std::map<u64,mmio_pa_range *> {
public:
  mmio_pa_range *find_range(u64 pa)
  {
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
  : public std::map<u64,mmio_va_range *> {
public:
  mmio_va_range *find_range(u64 va)
  {
    auto it = lower_bound(va);
    if (it == begin())
      return nullptr;

    if (it != end())
      if (it->second->va <= va && va < it->second->va_end)
	return it->second;

    --it;

    if (it == begin())
      return nullptr;

    if (it->second->va <= va && va < it->second->va_end)
      return it->second;

    return nullptr;
  }

  void insert_range(mmio_va_range *range)
  {
    mmio_va_range *oldrange = find_range(range->va);
    if (oldrange != nullptr)
      return;

    (*this)[range->va] = range;
  }

  mmio_va_range *virtualize_range(mmio_va_range *range, u64 oldva, u64 va, u64 va_end)
  {
    mmio_va_range *newrange = range->virtualize(oldva, va, va_end);
    //print(mmio_log, "newrange at %016lx-%016lx (%016lx)\n",
    //  newrange->va, newrange->va_end, va);
    insert_range(newrange);
    return newrange;
  }
};

mmio_va_range *mmio_pa_range::virtualize(u64 pa, u64 va, u64 va_end)
{
  u64 off = pa - this->pa;
  mmio_va_range *ret = new mmio_va_range(this, off, va, va_end);

  return ret;
}

static mmio_pa_table mmio_pa_ranges;
static mmio_table mmio_va_ranges;

#define PAGE_SIZE (16384)

void
mmio_pa_range_pt::store(mmio_insn *insn, u64 pa, u128 val)
{
  if (insn->size == 16) {
    insn->size = 8;
    mmio_pa_range_pt::store(insn, pa, val & U64_MAX);
    insn->va += 8;
    mmio_pa_range_pt::store(insn, pa, val >> 64);
    return;
  }
  if (insn->size != 8)
    abort();
  pa_range_cache->store(insn, pa, val);
  if (val & 1) {
    u64 pte = val;
    u64 mapped_pa = val & PAGE_TABLE_PAGE_MASK;
    u64 mapped_va = offs_to_va2(pterange.off0,
				pterange.off1,
				pterange.off2 + (pa & (PAGE_SIZE - 1)) / 8,
				1);
    print(mmio_log, "request to install mapping %016lx -> %016lx (%016lx %016lx)\n",
	  mapped_va, mapped_pa, pa, pte);
    auto pa_range = mmio_pa_ranges.find_range(mapped_pa);
    if (pa_range) {
      auto va_range = pa_range->virtualize(mapped_pa, mapped_va,
					   mapped_va + PAGE_SIZE);
      mmio_va_ranges.insert_range(va_range);
      print(mmio_log, "conflicting range %p\n", pa_range);
    } else
      pa_range_pa->store(insn, pa, val);
  }
}

u128
mmio_pa_range_pt::load(mmio_insn *insn, u64 pa)
{
  return pa_range_cache->load(insn, pa);
}

#if 0
class mmio_va_range_pt
  : public mmio_va_range_pa {
public:
  mmio_pterange pte[2048];
  u64 *fake;
  int level;
  unsigned long off0;
  unsigned long off1;
  unsigned long off2;

  virtual void store(mmio_insn *insn, u128 val);
  virtual u128 load(mmio_insn *insn);

  mmio_va_range_pt(mmio_pa_range *pa_range,
		   u64 pa, int level, unsigned long off0, unsigned long off1,
		   unsigned long off2)
    : mmio_va_range_pa(pa_range, pa, pa + 0x4000), level(level), off0(off0), off1(off1),
      off2(off2), fake(new u64[2048])
  {
    for (int i = 0; i < 2048; i++) {
      pte[i].level = level + 1;
      pte[i].va0 = offs_to_va2(off0, off1, off2, 1);
    }
  }

  mmio_va_range *virtualize(u64 oldva, u64 va, u64 va_end)
  {
    mmio_va_range_pt *newrange = new mmio_va_range_pt(pa_range, pa, level, off0, off1, off2);
    newrange->va = va;
    newrange->va_end = va_end;
    delete newrange->fake;
    newrange->fake = fake;
    return newrange;
  }
};

void mmio_va_range_pt::store(mmio_insn *insn, u128 val)
{
  if (val & 1) {
    u64 pa = val & 0xfffffff000;
    mmio_va_range *range = mmio_va_ranges.find_range(pa);
    print(mmio_log, "request to install mapping for %016lx, range %p\n", pa,
	  range);
    if (range) {
      print(mmio_log, "prohibiting!\n%s", "");
      u64 mapped_va = offs_to_va2(off0, off1, off2 + i, 1);
      mmio_va_ranges.insert_range(range->virtualize(range->va,
						    offs_to_va2(off0, off1, off2 + i, 1),
						    offs_to_va2(off0, off1, off2 + i, 1) + 0x4000));
      print(mmio_log, "prohibited write to page table at %016lx/%016lx\n",
	    insn->va, mapped_va);
      return;
    }
  }

  mmio_va_range_pa::store(insn, val);
}

u128 mmio_va_range_pt::load(mmio_insn *insn)
{
  u128 ret = fake[(insn->va & 0x3ff8)/8];
  print(mmio_log, "wait, who's reading a page table? %016lx -> %016lx\n",
	insn->elr, (u64)ret);
  return ret;
  // handle pt stuff
  u64 off = (insn->va >> 3) & 2047;
  u64 off_end = off + 2;
  if (off_end > 2048)
    off_end = 2048;
  u64 addr = off0 << (14 + 11 + 11);
  return mmio_va_range_pa::load(insn);
}
#endif

void mmio_pa_range::store(mmio_insn *, u64, u128)
{
}

u128 mmio_pa_range::load(mmio_insn *, u64)
{
  return 0;
}

void mmio_pa_range_pa::store(mmio_insn *insn, u64 pa, u128 val)
{
  switch (insn->size) {
  case 4:
    write32(pa, (unsigned) val);
    break;
  case 16:
    write64(pa, (unsigned long) val);
    write64(pa + 8, (unsigned long) (val >> 64));
    break;
  case 8:
    write64(pa, (unsigned long) val);
    break;
  }
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
    print(mmio_log, "read %016lx\n", ret);
    return ret;
  }
  }
  return 0;
}

class mmio_va_range_nop
  : public mmio_va_range {
public:
  virtual void store(mmio_insn *, u128) {}
  virtual u128 load(mmio_insn *)
  {
    return 0;
  }

  virtual std::string note()
  {
    return " [ignored]";
  }

  virtual mmio_va_range *virtualize(u64 oldva, u64 newva, u64 newva_end)
  {
    return new mmio_va_range_nop(newva, newva_end);
  }

  mmio_va_range_nop(u64 start, u64 end)
    : mmio_va_range(nullptr, 0, start, end) {}
};

class mmio_pa_range_fwd
  : public mmio_pa_range
{
public:
  mmio_pa_range *lower;
  mmio_pa_range_fwd(mmio_pa_range *lower)
    : lower(lower) {}
};

class mmio_pa_range_log
  : public mmio_pa_range_fwd
{
public:
  mmio_pa_range_log(mmio_pa_range *lower)
    : mmio_pa_range_fwd(lower) {}
};

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

class mmio_va_range_log
  : public mmio_va_range
{
public:
  mmio_va_range *lower;

  mmio_va_range_log(mmio_va_range *lower)
    : lower(lower), mmio_va_range(nullptr, 0, va, va_end)
  {
    this->va = lower->va;
    this->va_end = lower->va_end;
  }

  virtual u128 load(mmio_insn *insn);
  virtual void store(mmio_insn *insn, u128 val);

  virtual mmio_va_range *virtualize(u64 oldva, u64 newva, u64 newva_end)
  {
    return new mmio_va_range_log(lower->virtualize(oldva, newva, newva_end));
  }
};

class mmio_va_range_cache
  : public mmio_va_range
{
public:
  u128 *buf;

  mmio_va_range_cache(u64 va, u64 va_end)
    : mmio_va_range(nullptr, 0, va, va_end)
  {
    this->va = va;
    this->va_end = va_end;
    buf = new u128[(va_end - va + 15)/16];
  }

  virtual void store(mmio_insn *insn, u128 val);
};

void mmio_va_range_cache::store(mmio_insn *insn, u128 val)
{
  memcpy(((char *)buf) + (insn->va - va), &val, insn->size);
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

void mmio_va_range_log::store(mmio_insn *insn, u128 val)
{
  print(mmio_log, "storing\n", "");
  usleep(1000000);
  switch (insn->size) {
  default:
    print(mmio_log,
	  "%016lx <- %lx {%016lx/%016lx}%s", lower->loggable_address(insn->va),
	  (long)val, insn->elr, va_to_baseoff(insn->elr, insn->level0),
	  note().c_str());
  }
}

u128 mmio_va_range_log::load(mmio_insn *insn)
{
  print(mmio_log, "loading\n", "");
  usleep(1000000);
  u128 val = lower->load(insn);
  switch (insn->size) {
  default:
    print(mmio_log,
	  "%016lx -> %lx {%016lx/%016lx}%s", lower->loggable_address(insn->va),
	  (long)val, insn->elr, va_to_baseoff(insn->elr, insn->level0),
	  note().c_str());
  }

  return val;
}

class mmio_va_range_ignore
  : public mmio_va_range
{
  virtual bool handle_insn(mmio_insn *insn);
};

#if 0
class mmio_delay_decay {
  double delay;
  double decay;
};

class mmio_va_range_delay
  : public mmio_va_range {
  mmio_delay_decay *delay_decay;

  mmio_va_range *lower;

  mmio_va_range_delay(mmio_va_range *lower, double delay = .025, double decay = .999)
    : lower(lower), delay(delay), decay(decay), mmio_va_range(nullptr)
  {
  }
};
#endif

void mmio_va_range::insn_side_effects(unsigned long frame, unsigned insn,
				   unsigned long level0)
{
}

bool mmio_va_range::handle_insn(mmio_insn *insn)
{
  u32 insn32 = insn->get_insn();
  //print(mmio_log, "handle_insn %08x\n", insn32);
  int t = (insn32 & 31);
  if (insn32 == 0xb8004669) {
    int n = (insn32 >> 5) & 31;
    write_reg(insn->frame, n, read_reg(insn->frame, n, insn->level0) + 4, insn->level0);
    insn32 = 0xb8600809;
  }
  if ((insn32 & 0xffe00c00) == 0xb8600800 ||
      (insn32 & 0xffe00000) == 0xb9400000) {
    /* 32-bit LDR (register, unsigned offset) */
    insn->size = 4;
    print(mmio_log, "32-bit load %08x\n", insn32);
    u128 val = load(insn);
    write_reg(insn->frame, t, val, insn->level0);
    return true;
  }
  if ((insn32 & 0xffe00c00) == 0xb8200800 ||
      (insn32 & 0xffe00000) == 0xb9000000) {
    /* 32-bit STR (register, unsigned offset) */
    insn->size = 4;
    print(mmio_log, "32-bit store %08x\n", insn32);
    u128 val = read_reg(insn->frame, t, insn->level0);
    store(insn, val);
    return true;
  }
  if ((insn32 & 0xffe00c00) == 0xf8600800 ||
      (insn32 & 0xffc00000) == 0xf9400000) {
    /* 64-bit LDR (register, unsigned offset) */
    insn->size = 8;
    u128 val = load(insn);
    //print(mmio_log, "64-bit load %08x\n", insn32);
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
    print(mmio_log, "128-bit load %08x\n", insn32);
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
    print(mmio_log, "128-bit store %08x\n", insn32);
    u64 val0 = read_reg(insn->frame, t, insn->level0);
    u64 val1 = read_reg(insn->frame, t2, insn->level0);
    u128 val = val0 + ((u128)val1 << 64);
    store(insn, val);
    return true;
  }
  print(mmio_log, "unhandled insn %08x {%016lx / %016lx}\n", insn32,
	insn->elr, va_to_baseoff(insn->elr, insn->level0));
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

#if 0
void read_table(FILE *f)
{
  unsigned long start, stop, action;
  while (fscanf(f, "%ld %ld %ld\n", &start, &stop, &action) == 3) {
    mmio_va_range *range = new mmio_va_range_pa(start, stop);
    range = new mmio_va_range_log(range);
    mmio_va_ranges.insert_range(range);
  }
}
#endif

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

  for (unsigned long off0 = 0; off0 < 2048; off0++) {
    u64 pte1 = read64(pt + 8 * off0);
    u64 level1 = pte1 & 0xfffffff000;
    if ((pte1 & 3) == 3) {
      for (unsigned long off1 = 0; off1 < 2048; off1++) {
	u64 pte2 = read64(level1 + 8 * off1);
	u64 level2 = pte2 & 0xfffffff000;
	if ((pte2 & 3) == 3) {
	  for (unsigned long off2 = 0; off2 < 2048; off2++) {
	    u64 pte3 = read64(level2 + 8 * off2);
	    u64 page = pte3 & 0xfffffff000;
	    u64 va = offs_to_va2(off0, off1, off2, 1);
	    if (pte3 & 1) {
	      mmio_pterange p;
	      p.pa0 = page;
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
	  mmio_pterange p;
	  p.pa0 = level2;
	  p.va0 = offs_to_va2(off0, off1, 0, 1);
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

static void steal_page_table(u64 pt)
{
  auto ranges = pt_ranges(pt);
  std::multimap<u64,std::pair<u64,u64>> pt_vas;
  std::set<u64> pts;
  bool didsomething = true;
  pts.insert(pt);
  while (didsomething) {
    didsomething = false;
    for (unsigned long off0 = 0; off0 < 2048; off0++) {
      u64 pte1 = read64(pt + 8 * off0);
      u64 level1 = pte1 & 0xfffffff000;
      if (!pts.count(level1)) {
	didsomething = true;
	pts.insert(level1);
      }
      if ((pte1 & 3) == 3) {
	for (unsigned long off1 = 0; off1 < 2048; off1++) {
	  u64 pte2 = read64(level1 + 8 * off1);
	  u64 level2 = pte2 & 0xfffffff000;
	  if (!pts.count(level2)) {
	    didsomething = true;
	    pts.insert(level2);
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
  print(mmio_log, "found %ld page table pages\n", pts.size());
  for (auto pte : ranges) {
    for (auto page : pte.pages()) {
      if (pts.count(page)) {
	auto pa_range = new mmio_pa_range_pt(page, page + 0x4000,
					     pte);
	mmio_pa_ranges.insert_range(pa_range);
      }
    }
  }
  for (auto pte : ranges) {
    if (pts.count(pte.pa0)) {
      auto pa_range = mmio_pa_ranges.find_range(pte.pa0);
      auto va_range = pa_range->virtualize(pte.pa0, pte.va0, pte.va0 + 0x4000);
      mmio_va_ranges.insert_range(va_range);
      write64(pte.ptep, 0);
    }
  }
  for (unsigned long off0 = 0; off0 < 2048; off0++) {
    u64 pte1 = read64(pt + 8 * off0);
    u64 level1 = pte1 & 0xfffffff000;
    if ((pte1 & 3) == 3) {
      for (unsigned long off1 = 0; off1 < 2048; off1++) {
	u64 pte2 = read64(level1 + 8 * off1);
	u64 level2 = pte2 & 0xfffffff000;
	auto pa_range = mmio_pa_ranges.find_range(level2);
	
	if ((pte2 & 3) == 3) {
	  for (unsigned long off2 = 0; off2 < 2048; off2++) {
	    u64 pte3 = read64(level2 + 8 * off2);
	    u64 page = pte3 & 0xfffffff000;
	    u64 va = offs_to_va2(off0, off1, off2, 1);
	    if (pte3 & 1) {
#if 0
	      if (pts.count(page)) {
		mmio_pa_range_pt *range;
	      }
	      if (pts.count(page)) {
		mmio_va_range_pt *range =
		  new mmio_va_range_pt
		  (new mmio_pa_range_pt(page, page + 0x4000),
		   page, 3, off0, off1, off2);
		for (int i = 0; i < 2048; i++)
		  range->fake[i] = read64(page + 8 * i);
		mmio_va_ranges.insert_range(range);
		mmio_va_ranges.virtualize_range(range,
					     range->va, va, va + 0x4000);
	      }
#endif
	    }
	  }
	} else if (pte2 & 1) {
	  print(mmio_log, "found large block %016lx\n", level2);
	  for (u64 pa = level2; pa < level2 + 0x1fffff; pa += 0x4000) {
	    if (pts.count(pa)) {
	      print(mmio_log, "oh no, page table in large block at %016lx\n",
		    pa);
	    }
	  }
	}
      }
    }
  }
  for (unsigned long off0 = 0; off0 < 2048; off0++) {
    u64 pte1 = read64(pt + 8 * off0);
    u64 level1 = pte1 & 0xfffffff000;
    if ((pte1 & 3) == 3) {
      for (unsigned long off1 = 0; off1 < 2048; off1++) {
	u64 pte2 = read64(level1 + 8 * off1);
	u64 level2 = pte2 & 0xfffffff000;
	if ((pte2 & 3) == 3) {
	  for (unsigned long off2 = 0; off2 < 2048; off2++) {
	    u64 pte3 = read64(level2 + 8 * off2);
	    u64 page = pte3 & 0xfffffff000;
	    u64 va = offs_to_va2(off0, off1, off2, 1);
	    if (pte3 & 1) {
	      if (pts.count(page)) {
		write64(level2 + 8 * off2, 0);
	      }
	    }
	  }
	} else if (pte2 & 1) {
	  print(mmio_log, "found large block %016lx\n", level2);
	  for (u64 pa = level2; pa < level2 + 0x1fffff; pa += 0x4000) {
	    if (pts.count(pa)) {
	      print(mmio_log, "oh no, page table in large block at %016lx\n",
		    pa);
	    }
	  }
	}
      }
    }
  }
  for (auto pterange : ranges) {
    for (auto page : pterange.pages()) {
      if (pts.count(page)) {
	auto range = mmio_va_ranges.find_range(page);
	if (!range) {
	  print(mmio_log, "%016lx -> %016lx not found!\n", page, page);
	} else {
	  mmio_va_ranges.virtualize_range(range, range->va,
					  pterange.va0, pterange.va0 + 0x4000);
	}
      }
      if (pts.count(page)) {
	auto range = mmio_va_ranges.find_range(pterange.va0);
	if (!range)
	  print(mmio_log, "%016lx -> %016lx not found!\n", pterange.va0, page);
      }
    }
  }
}

static void handle_mmio()
{
  //print(mmio_log, "handling mmio!%s\n", "");
#if 0
  u64 pt0 = read64(ppage + 0x3fe0);
  for (unsigned long off0 = 0; off0 < 2048; off0++) {
    u64 pte1 = read64(pt0 + 8 * off0);
    u64 level1 = pte1 & 0xfffffff000;
    if ((pte1 & 3) == 3) {
      for (unsigned long off1 = 0; off1 < 2048; off1++) {
	u64 pte2 = read64(level1 + 8 * off1);
	u64 level2 = pte2 & 0xfffffff000;
	if ((pte2 & 3) == 3) {
	  for (unsigned long off2 = 0; off2 < 2048; off2++) {
	    u64 pte3 = read64(level2 + 8 * off2);
	    u64 page = pte3 & 0xfffffff000;
	    if (pte3 & 1) {
	      print(mmio_log, "found page table at (%016lx %016lx %016lx), unmapping\n", pt0 + 8 * off0, level1 + 8 * off1, level2 + 8 * off2);
	    }
	  }
	} else if ((pte2 & 3) == 1) {
	  print(mmio_log, "found large block %016lx-%016lx at %016lx %016lx\n",
		pte2,
		level2 + (1 << (14 + 11)), pt0 + 8 * off0, level1 + 8 * off1);
	}
      }
    } else if ((pte1 & 3) == 1) {
      print(mmio_log, "found huge block %016lx at %016lx\n",
	    pte1, pt0 + 8 * off0);
    }
  }
#endif
  if (read64(ppage + 0x3f08) != 0x141ef) {
    steal_page_table(read64(ppage + 0x3fe8));
    write64(ppage + 0x3f08, 0x141ef);
  }
#if 0
  u64 pt1 = read64(ppage + 0x3fe8);
  for (unsigned long off0 = 0; off0 < 2048; off0++) {
    u64 pte1 = read64(pt1 + 8 * off0);
    u64 level1 = pte1 & 0xfffffff000;
    if ((pte1 & 3) == 3) {
      for (unsigned long off1 = 0; off1 < 2048; off1++) {
	u64 pte2 = read64(level1 + 8 * off1);
	u64 level2 = pte2 & 0xfffffff000;
	if ((pte2 & 3) == 3) {
	  for (unsigned long off2 = 0; off2 < 2048; off2++) {
	    u64 pte3 = read64(level2 + 8 * off2);
	    u64 page = pte3 & 0xfffffff000;
	    if (pte3 & 1) {
	      if (page == pt1)
		print(mmio_log, "found page table[1] %016lx -> %016lx at (%016lx %016lx %016lx), unmapping\n", offs_to_va2(off0, off1, off2, 1), page, pt1 + 8 * off0, level1 + 8 * off1, level2 + 8 * off2);
	    }
	  }
	} else if ((pte2 & 3) == 1) {
	  print(mmio_log, "found large block %016lx at %016lx %016lx\n",
		pte2, pt1 + 8 * off0, level1 + 8 * off1);
	}
      }
    } else if ((pte1 & 3) == 1) {
      print(mmio_log, "found huge block %016lx at %016lx\n",
	    pte1, pt1 + 8 * off0);
    }
  }
  if (read64(ppage + 0x3f08) == 0xb9000c000) {
    print(mmio_log, "page table already stolen. (%016lx)\n", read64(ppage + 0x3fe8));
  } else {
#if 0
    for (int i = 0; i < 2048; i++) {
      u64 pte = read64(read64(ppage + 0x3fe8) + 8 * i);
      write64(0xb9000c000 + 8 * i, pte);
      u64 addr = pte & 0xfffffff000;
      if ((pte & 3) == 3) {
	write64(read64(ppage + 0x3fe8) + 8 * i, copypage(addr));
      } else if (pte & 1) {
	print(mmio_log, "cannot handle large block (%016lx)\n", pte);
      }
    }
    write64(ppage + 0x3f08, 0xb9000c000);
#endif
    print(mmio_log, "stealing page table (%016lx)\n", read64(ppage + 0x3fe8));
  }
#endif
  u64 success = 0;
  u64 esr = read64(ppage + 0x3fd8);
  u64 elr = read64(ppage + 0x3ff8);
  if ((esr & 0xf8000000UL) != 0x90000000UL) {
    write64(ppage + 0x3fd0, success);
    asm volatile("dmb sy" : : : "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    write64(ppage + 0x3ff0, 0);
    return;
  }
  if (esr == 0x9600004f) {
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
#if 0
    if (1) {
      unsigned long addr = far;
      unsigned long off0 = (addr >> (14 + 11 + 11)) & 2047;
      unsigned long off1 = (addr >> (14 + 11)) & 2047;
      unsigned long off2 = (addr >> (14)) & 2047;
      unsigned long level0 = read64(ppage + 0x3fe8) & 0xfffffff000;
      if (!(read64(level0 + off0 * 8) & 1))
	return 1;
      unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
      if (!(read64(level1 + off1 * 8) & 1))
	return 1;
      unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
      if (!(read64(level2 + off2 * 8) & 1))
	return 1;
      write64(level2 + off2 * 8, read64(level2 + off2 * 8) &~ 1L);
    }
#endif
    write64(ppage + 0x3ff0, 0);
    print(mmio_log, "interrupt event %08lx\n", event);
    //write64_to_va(va, event, read64(ppage + 0x3fe8));
    return;
  }
  u64 far = read64(ppage + 0x3ff0);
  mmio_va_range *range = mmio_va_ranges.find_range(far);

  if (!range) {
    print(mmio_log, "unknown far %016lx\n", far);
    sleep(1);
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

  success = range->handle_insn(&insn);
  if (success) {
    write64(ppage + 0x3ff8, elr + 4);
  }

  if (!success)
  print(mmio_log, "success: %d\n", success);
  write64(ppage + 0x3fd0, success);
  asm volatile("dmb sy" : : : "memory");
  asm volatile("dsb sy");
  asm volatile("isb");
  write64(ppage + 0x3ff0, 0);
  return;
}

static void reread_page_table(u64 level0, int high)
{
  unsigned long new_level0 = high ? 0xb9000c000 : 0xb90008000;
  //print(mmio_log, "level0 %016lx\n", level0);
  unsigned long off0, off1, off2;
  for (off0 = 0; off0 < 2048; off0++) {
    u64 pte1 = read64(level0 + off0 * 8);
    if (!(pte1 & 1))
      continue;
    if ((pte1 & 3) == 1)
      continue;
    u64 level1 = pte1 & 0xfffffff000;
    u64 new_pte1 = (pte1 &~ level1) | alloc_page();
    u64 new_level1 = new_pte1 & 0xffffffff000;
    write64(new_level0 + 8 * off0, new_pte1);
    //print(mmio_log, "level1 %016lx\n", level1);
    for (off1 = 0; off1 < 2048; off1++) {
      u64 pte2 = read64(level1 + off1 * 8);
      if ((pte2 & 3) == 1) {
	//f(pte2, offs_to_va(off0, off1, 0), 2, cookie);
	continue;
      }
      if (!(pte2 & 1))
	continue;
      u64 level2 = pte2 & 0xfffffff000;
      u64 new_pte2 = (pte2 &~ level2) | alloc_page();
      u64 new_level2 = new_pte2 & 0xffffffff000;
      write64(new_level1 + 8 * off1, new_pte2);
      //print(mmio_log, "level2 %016lx\n", level2);
      for (off2 = 0; off2 < 2048; off2++) {
	u64 pte3 = read64(level2 + off2 * 8);
	if (!(pte3 & 1))
	  continue;
	u64 level3 = pte3 & 0xfffffff000;

	write64(new_level2 + 8 * off2, pte3);
	//print(mmio_log, "level3 %016lx\n", level3);
	mmio_va_range *range = mmio_va_ranges.find_range(level3);
	if (range) {
	  u64 va = offs_to_va2(off0, off1, off2, high);

	  mmio_va_ranges.virtualize_range(range, level3, va &~ 0x3fffL,
				       (va | 0x3fffL) + 1);
	  static int count = 0;
	  if (count++ < 100)
	    print(mmio_log, "unmapping pte %016lx at %016lx\n", pte3, va);
	  write64(level2 + off2 * 8, pte3 &~ 1L);
	}
      }
    }
  }
}

static void reread_page_tables()
{
  reread_page_table(read64(ppage + 0x3e08), 1);
  reread_page_table(read64(ppage + 0x3e10), 0);
}

static std::vector<u64> pt_addrs;
static void handle_pt(u64 addr)
{
  //print(mmio_log, "PT changed, rereading%s\n", "");
  reread_page_tables();
  if (read64(addr) == MAGIC_WORD) {
    //print(mmio_log, "continuing after PT change%s\n", "");
    write64(addr, 0);
  }
}

static unsigned long base;

bool sometimes()
{
  static time_t last_time;
  time_t this_time = time(NULL);
  if (this_time - last_time > 5) {
    last_time = this_time;
    return true;
  }
  return false;
}

void mainloop()
{
  if (read64(ppage + 0x3ff0) != 0) {
    handle_mmio();
  } else {
    for (auto addr : pt_addrs) {
      if (read64(addr) == MAGIC_WORD) {
	handle_pt(addr);
	return;
      }
    }
    if (sometimes()) {
      for (u64 addr = 0x800000000; addr < 0xa00000000; addr += 16384) {
	if (read64(addr) == MAGIC_WORD) {
	  for (auto addr2 : pt_addrs)
	    if (addr == addr2)
	      return;
	  print(mmio_log, "new PT addr %016lx\n", addr);
	  pt_addrs.push_back(addr);
	}
      }
    }
  }
}

int main2(int argc, char **argv)
{
  if (strcmp(argv[1], "unmap-pa") == 0) {
    char *range = argv[1];
    while (range && range[0]) {
      unsigned long addr = strtoll(range, &range, 0), addr2;
      if (range[0] == '-') {
	addr2 = strtoll(range + 1, &range, 0);
      } else {
	addr2 = addr + 0x3fff;
      }
      unmap_pa_range(addr, addr2);
      if (range[0] == ',') {
	range++;
      }
    }
  }
  log = fopen("/mmio-log", "a");
  if (!log)
    log = stdout;
  //write64(ppage + 0x3ff8, 0xffffffff);
  write64(ppage + 0x3fb0, 0);
  printf("initialized\n");
  asm volatile("dmb sy");
  asm volatile("dsb sy");
  asm volatile("isb");
  unsigned long far;

  write64(ppage + 0x3e00, 0xffffffff);
  while (true) {
    bool success = false;
    while ((far = read64(ppage + 0x3ff0)) == 0)
      sched_yield();
    unsigned long esr = read64(ppage + 0x3fd8);
    unsigned long elr = read64(ppage + 0x3ff8);
    if ((esr & 0xfc000000UL) != 0x54000000UL) {
      if ((esr & 0xfc000000UL) == 0x88000000) {
	static int seen = 0;
	if (!seen) {
	  seen = 1;
	  printf("received brk esr %016lx at %016lx!\n", esr, elr);
	}
      } else {
	//printf("received brk esr %016lx at %016lx!\n", esr, elr);
      }
    }
    if ((esr & 0x0f8000000UL) != 0x090000000UL) {
      write64(ppage + 0x3fd0, success);
      asm volatile("dmb sy" : : : "memory");
      asm volatile("dsb sy");
      asm volatile("isb");
      write64(ppage + 0x3ff0, 0);
      continue;
    }
    if ((esr & 0xf8000000) == 0x90000000) {
      //print("event %08lx\n", esr);
      unsigned long va;
      if ((va = read64(ppage + 0x3fb0))) {
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
	if (1) {
	  unsigned long addr = far;
	  unsigned long off0 = (addr >> (14 + 11 + 11)) & 2047;
	  unsigned long off1 = (addr >> (14 + 11)) & 2047;
	  unsigned long off2 = (addr >> (14)) & 2047;
	  unsigned long level0 = read64(ppage + 0x3fe8) & 0xfffffff000;
	  if (!(read64(level0 + off0 * 8) & 1))
	    return 1;
	  unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
	  if (!(read64(level1 + off1 * 8) & 1))
	    return 1;
	  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
	  if (!(read64(level2 + off2 * 8) & 1))
	    return 1;
	  write64(level2 + off2 * 8, read64(level2 + off2 * 8) &~ 1L);
	}
	write64(ppage + 0x3ff0, 0);
	print(mmio_log, "interrupt event %08lx\n", event);
	//write64_to_va(va, event, read64(ppage + 0x3fe8));
	continue;
      }
      do {
	unsigned insn = 0;

	unsigned long va = far;
	unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
	unsigned long off1 = (va >> (14 + 11)) & 2047;
	unsigned long off2 = (va >> (14)) & 2047;
	unsigned long level0 = read64(ppage + 0x3e08);
	if (!(read64(level0 + off0 * 8) & 1))
	  break;
	unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
	if (!(read64(level1 + off1 * 8) & 1))
	  break;
	unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
	if (!(read64(level2 + off2 * 8) & 1)) {
	  //print("esr %016lx elr %016lx\n", esr, elr);
	  //print("esr %016lx elr %016lx\n", esr, elr);
	  unsigned long pa, va, action;
	  FILE *f = fopen("/mmio-map", "r");
	  while (fscanf(f, "%ld %ld %ld\n", &pa, &va, &action) == 3) {
	    if ((read64(level2 + off2 * 8) & 0xffffffc000) == pa) {
	      success = true;
	      insn = insn_at_va(elr, read64(ppage + 0x3fe8));
	      if (simulate_insn(read64(ppage + 0x3fc8), insn, elr, far, pa,
				read64(ppage + 0x3fe8), action)) {
		static int count = 32768;
		if (count-- == 0) {
		  count = 32768;
		  //sleep(10);
		}
		write64(ppage + 0x3ff8, elr + 4);
		write64(ppage + 0x3fd0, success);
		asm volatile("dmb sy");
		asm volatile("dsb sy");
		asm volatile("isb");
		write64(ppage + 0x3ff0, 0);
	      } else {
		write64(level2 + off2 * 8, read64(level2 + off2 * 8) | 1);
		write64(ppage + 0x3fd0, success);
		asm volatile("dmb sy");
		asm volatile("dsb sy");
		asm volatile("isb");
		write64(ppage + 0x3ff0, 0);
		print(mmio_log,
		      "remapping page at %016lx %016lx after %08x, %08x, %08x at %016lx\n", pa, va,
		      insn, insn_at_va(elr, read64(ppage + 0x3fe8)),
		      insn_at_va(elr, read64(ppage + 0x3fe0)),
		      elr);
	      }
	      break;
	    }
	  }
	  fclose (f);
	}
	unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
	if (success) {
#if 0
	  print("FAR %016lx ELR %016lx ESR %016lx insn %08x\n", far, elr, esr,
		insn);

	  print("PA %016lx\n", level3);
	  fflush(stdout);
#endif
	}
      } while (0);
      if (!success) {
	write64(ppage + 0x3fd0, success);
	asm volatile("dmb sy");
	asm volatile("dsb sy");
	asm volatile("isb");
	write64(ppage + 0x3ff0, 0);
      }
    } else if ((esr & 0xfc000000 == 0xf0000000)) {
    } else if ((esr & 0xfc000000 == 0xf0000000)) {
      // handle BRK
    }
  }
}

static void start_pt()
{
}

static void start_mmio()
{
  write64(ppage + 0x3fb0, 0);
  write64(ppage + 0x3e00, 0xffffffff);
}

int main(int argc, char **argv)
{
  mmio_log = fopen("/mmio-log", "a");
  if (!mmio_log)
    mmio_log = stdout;

  pt_log = fopen("/pt-log", "a");
  if (!pt_log)
    pt_log = stdout;

  base = read64(0xac0000008);
  mmio_pa_ranges.insert_range
    (new mmio_pa_range_log
     (new mmio_pa_range_nop(0x23d2b0000, 0x23d2c0000)));
#if 0
  mmio_va_ranges.insert_range
    (new mmio_va_range_log
     (new mmio_va_range_nop(0x23d2b0000, 0x23d2c0000)));
  mmio_va_ranges.insert_range
    (new mmio_va_range_log
     (new mmio_va_range_pa(new mmio_pa_range_pa(0x200000000, 0x23b000000))));
  mmio_va_ranges.insert_range
    (new mmio_va_range_log
     (new mmio_va_range_pa(new mmio_pa_range_pa(0x23b200000, 0x300000000),
			   0x23b200000, 0x300000000)));
  mmio_va_ranges.insert_range
    (new mmio_va_range_log
     (new mmio_va_range_pa(new mmio_pa_range_pa(0xbdf438000, 0xbe03d8000))));
#endif

  pt_addrs.push_back(base + 0x3e70000 + (0x8097cc000 - 0x804dd0000));
  pt_addrs.push_back(base + 0x3e74000 + (0x8097cc000 - 0x804dd0000));

  start_mmio();
  start_pt();

  while (true)
    mainloop();
  return 0;
}
