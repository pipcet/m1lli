#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#include <sched.h>

#include "ptstuff.h"

static FILE *log;

#define print(fmt, ...) do {						\
    struct timeval tv;							\
    gettimeofday(&tv, NULL);						\
    fprintf(log, "[%16ld.%06ld] " fmt, (long)tv.tv_sec, (long)tv.tv_usec, __VA_ARGS__); \
    fflush(log);							\
  } while (0)

bool simulate_insn(unsigned long frame, unsigned insn,
		   unsigned long elr, unsigned long va,
		   unsigned long pa, unsigned long level0,
		   unsigned long action)
{
  pa &= ~0x3fffL;
  pa |= (va & 0x3fffL);

  int t = insn & 31;
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
      //install_page(0xfffffff000004000,
      //	    0x23b100000, 3, read64(ppage + 0x3fe0));
      print("triggering interrupt event with address %016lx [%016lx/%016lx] -> x%d\n",
	    (pa & 0x3fff), read64(ppage + 0x3fb8),read64(ppage + 0x3fb0), t);
      print("TTBR %016lx %016lx %016lx frame %016lx\n",
	    read64(ppage + 0x3fe8), read64(ppage + 0x3fe0), read64(ppage + 0x3e08), frame);
      return false;
    } else if ((pa & ~0x3fffL) == 0x23b100000) {
      print("[unhandled?]interrupt %016lx!\n", pa);
    } else {
      u64 val = read32(pa);
      print("%016lx -> %08lx\n", pa, val);
      write_reg(frame, t, val, level0);
      return true;
    }
  }
  if ((pa & 0xffffffffffffc000) == 0x23b100000) {
    print("[unhandled]interrupt %016lx!\n", pa);
    return false;
  }
  if ((insn & 0xffe00c00) == 0xb8200800 ||
      (insn & 0xffe00000) == 0xb9000000) {
    /* 32-bit STR (register, unsigned offset) */
    print("%016lx <- %08lx\n", pa, read_reg(frame, t, level0));
    if (action)
      write32(pa, read_reg(frame, t, level0));
    return true;
  }
  if ((insn & 0xffe00c00) == 0xf8200800 ||
      (insn & 0xffe00000) == 0xf9000000) {
    /* 64-bit STR (register, unsigned offset) */
    print("%016lx <- %016lx\n", pa, read_reg(frame, t, level0));
    if (action)
      write64(pa, read_reg(frame, t, level0));
    return true;
  }
  if ((insn & 0xffe00c00) == 0xf8600800 ||
      (insn & 0xffe00000) == 0xf9400000) {
    /* 64-bit LDR (register, unsigned offset) */
    u64 val = read64(pa);
    print("%016lx -> %016lx\n", pa, val);
    write_reg(frame, t, val, level0);
    return true;
  }
  if ((insn == 0xb8004669)) {
    /* 32-bit STR (register, unsigned offset) */
    int n = (insn >> 5) & 31;
    print("%016lx <- %08lx\n", pa, read_reg(frame, t, level0));
    if (action)
      write32(pa, read_reg(frame, t, level0));
    write_reg(frame, n, read_reg(frame, n, level0) + 4, level0);
    return true;
  }
  print("unhandled insn %08x\n", insn);
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

int main(int argc, char **argv)
{
  unsigned long base = read64(0xac0000008);
  log = fopen("/pt-log", "a");
  if (!log)
    log = stdout;
  if (argv[1] && strcmp(argv[1], "clear") == 0) {
    unsigned long addrs[] = {
      base + (0x8097cc000 - 0x804dd0000),
      base + 0x3e70000 + (0x8097cc000 - 0x804dd0000),
      base + 0x3e74000 + (0x8097cc000 - 0x804dd0000),
      argv[2] ? strtoll(argv[2], NULL, 0) : 0,
    };
    unsigned long addr;
    for (int i = 0; i < ARRAYELTS(addrs); i++) {
      addr = addrs[i];
      if (addr && read64(addr) == 0x14000770d10303ff) {
	write64(addr, 0);
	exit(0);
      }
    }
    exit(1);
  }
  asm volatile("isb");
  int n = 0;
  unsigned long count;
  while (true) {
    unsigned long addrs[] = {
      base + (0x8097cc000 - 0x804dd0000),
      base + 0x3e70000 + (0x8097cc000 - 0x804dd0000),
      base + 0x3e74000 + (0x8097cc000 - 0x804dd0000),
      argv[1] ? strtoll(argv[1], NULL, 0) : 0,
    };
    unsigned long addr;
    while (true) {
      for (int i = 0; i < ARRAYELTS(addrs); i++) {
	addr = addrs[i];
	if (addr)
	  if ((count = read64(addr)) != 0)
	    goto found;
      }
      sched_yield();
      for (unsigned long offset = 0x800000000; offset < 0x900000000; offset += 16384) {
	if (read64(offset) == 0x14000770d10303ff) {
	  fprintf(stderr, "candidate %016lx at %016lx\n", read64(offset),
		  offset);
	  addr = offset;
	  goto found;
	}
      }
    }
  found:
    if (n-- == 0) {
      printf("%ld\n", addr);
      //printf("triggered, count %016lx, addr %016lx\n", count, addr);
      exit(0);
    } else {
      write64(addr, 0);
    }
  }
}
