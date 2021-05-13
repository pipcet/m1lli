#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "ptstuff.h"

#define print(fmt, ...) do {						\
    struct timeval tv;							\
    gettimeofday(&tv, NULL);						\
    printf("[%16ld.%06ld] " fmt, (long)tv.tv_sec, (long)tv.tv_usec, __VA_ARGS__); \
  } while (0)

bool simulate_insn(unsigned long frame, unsigned insn,
		   unsigned long elr, unsigned long va,
		   unsigned long pa, unsigned long level0)
{
  pa &= ~0x3fffL;
  pa |= (va & 0x3fffL);

  if ((insn & 0xffe00c00) == 0xb800400) {
    int n = (insn >> 5) & 31;
    int t = (insn & 31);
    int imm = (insn >> 12) & 0x1ff;
    if (imm & 0x100)
      imm = 0x200 - imm;
  }

  int t = (insn & 31);
  if ((insn & 0xffe00c00) == 0xb8200800) { /* 32-bit STR (register) */
    print("%016lx <- %08lx\n", pa, read_reg(frame, t, level0));
    write32(pa, read_reg(frame, t, level0));
    return true;
  } else if ((insn & 0xffe00c00) == 0xb8600800) { /* LDR (register) */
    u64 val = read32(pa);
    print("%016lx -> %08lx\n", pa, val);
    write_reg(frame, t, val, level0);
    return true;
  } else if ((insn & 0xffe00000) == 0xb9000000) { /* STR (unsigned offset) */
    print("%016lx <- %016lx\n", pa, read_reg(frame, t, level0));
    write32(pa, read_reg(frame, t, level0));
    return true;
  } else if ((insn & 0xffe00000) == 0xb9400000) { /* LDR (unsigned offset) */
    u64 val = read32(pa);
    print("%016lx -> %016lx\n", pa, val);
    write_reg(frame, t, val, level0);
    return true;
  }
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
    printf("unhandled insn %08x\n", insn);
    return false;
  }

  return true;
}

int main(void)
{
  write64(ppage + 0x3ff8, 0xffffffff);
  write64(ppage + 0x3ff0, 0);
  unsigned long far;

  write64(ppage + 0x3e00, 0xffffffff);
  while (true) {
    bool success = false;
    while ((far = read64(ppage + 0x3ff0)) == 0);
    unsigned long esr = read64(ppage + 0x3fd8);
    if ((esr & 0x0f8000000UL) != 0x090000000UL) {
      write64(ppage + 0x3fd0, success);
      write64(ppage + 0x3ff0, 0);
      continue;
    }
    if (far >= 0xf000000000000000) {
      do {
	unsigned long elr = read64(ppage + 0x3ff8);
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
	  unsigned long pa, va;
	  FILE *f = fopen("/mmio-map", "r");
	  while (fscanf(f, "%ld %ld\n", &pa, &va) == 2) {
	    if ((read64(level2 + off2 * 8) & 0xffffffc000) == pa) {
	      success = true;
	      insn = insn_at_va(elr, read64(ppage + 0x3fe8));
	      if (simulate_insn(read64(ppage + 0x3fc8), insn, elr, far, pa,
				read64(ppage + 0x3fe8))) {
		write64(ppage + 0x3ff8, elr + 4);
		write64(ppage + 0x3fd0, success);
		write64(ppage + 0x3ff0, 0);
	      } else {
		printf("remapping page at %016lx %016lx after %08x\n", pa, va,
		       insn, insn_at_va(elr, read64(ppage + 0x3fe8)),
		       insn_at_va(elr, read64(ppage + 0x3fe0)));
		write64(level2 + off2 * 8, read64(level2 + off2 * 8) | 1);
		write64(ppage + 0x3fd0, success);
		write64(ppage + 0x3ff0, 0);
	      }
	      break;
	    }
	  }
	  fclose (f);
	  if (!success) {
	    if ((read64(level2 + off2 * 8) & 0xffffffc000) == pa) {
	      success = true;
	      insn = insn_at_va(elr, read64(ppage + 0x3fe8));
	      if (simulate_insn(read64(ppage + 0x3fc8), insn, elr, far, pa,
				read64(ppage + 0x3fe8))) {
		write64(ppage + 0x3ff8, elr + 4);
		write64(ppage + 0x3fd0, success);
		write64(ppage + 0x3ff0, 0);
	      } else {
		printf("remapping unknown page at %016lx %016lx after %08x\n", pa, va,
		       insn);
		write64(level2 + off2 * 8, read64(level2 + off2 * 8) | 1);
		write64(ppage + 0x3fd0, success);
		write64(ppage + 0x3ff0, 0);
	      }
	    }
	  }
	}
	unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
	if (success) {
#if 0
	  printf("FAR %016lx ELR %016lx ESR %016lx insn %08x\n", far, elr, esr,
		 insn);

	  printf("PA %016lx\n", level3);
	  fflush(stdout);
	  fprintf(stderr, "FAR %016lx ELR %016lx ESR %016lx\n", far, elr, esr);

	  fprintf(stderr, "PA %016lx\n", level3);
	  fflush(stderr);
#endif
	}
      } while (0);
    }
    if (!success) {
      write64(ppage + 0x3fd0, success);
      write64(ppage + 0x3ff0, 0);
    }
  }
}
