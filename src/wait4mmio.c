#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sched.h>
#include <sys/time.h>

#include "ptstuff.h"

static FILE *log;

#define print(fmt, ...) do {						\
    struct timeval tv;							\
    gettimeofday(&tv, NULL);						\
    fprintf(log, "[%16ld.%06ld] " fmt, (long)tv.tv_sec, (long)tv.tv_usec, __VA_ARGS__); \
    fflush(log);							\
    if (1)fprintf(stderr, "[%16ld.%06ld] " fmt, (long)tv.tv_sec, (long)tv.tv_usec, __VA_ARGS__); \
    fflush(stderr);							\
    if (1) usleep(500000);						\
  } while (0)

bool simulate_insn(unsigned long frame, unsigned insn,
		   unsigned long elr, unsigned long va,
		   unsigned long pa, unsigned long level0,
		   unsigned long action)
{
  pa &= ~0x3fffL;
  pa |= (va & 0x3fffL);

  int t = insn & 31;
  static unsigned v23d2b000c = 0;
  print("handling insn %08lx at pa %016lx\n", insn, pa);
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
      print("triggering interrupt event with address %016lx [%016lx/%016lx] -> x%d\n",
	    (pa & 0x3fff), read64(ppage + 0x3fb8),read64(ppage + 0x3fb0), t);
      print("TTBR %016lx %016lx %016lx frame %016lx\n",
	    read64(ppage + 0x3fe8), read64(ppage + 0x3fe0), read64(ppage + 0x3e08), frame);
      return false;
    } else if ((pa & ~0x3fffL) == 0x23b100000) {
      print("[unhandled?]interrupt %016lx!\n", pa);
    } else {
      u64 val = action ? read32(pa) : 0;
      //if (pa == 0x23d2b000c)
      //val = read32(pa);
      print("%016lx -> %08lx {%016lx / %016lx}%s\n", pa, val, elr, va_to_baseoff(elr, level0), action ? "" : "[ignored]");
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
    u32 val;
    print("%016lx <- %08lx {%016lx / %016lx}%s\n", pa, read_reg(frame, t, level0),
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
    print("%016lx <- %016lx {%016lx / %016lx}%s\n", pa, read_reg(frame, t, level0),
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
    print("%016lx -> %016lx {%016lx / %016lx}%s\n", pa, val,
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
    print("%016lx -> %016lx%016lx {%016lx / %016lx}%s\n", pa, val0, val1,
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
    print("%016lx <- %016lx%016lx {%016lx / %016lx}%s\n", pa, val0, val1,
	  elr, va_to_baseoff(elr, level0),
	  action ? "" : " [ignored]");
    if (action) {
      write64(pa, val0);
      write64(pa + 8, val1);
    }
    return true;
  }
  print("unhandled insn %08x {%016lx / %016lx}\n", insn,
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

int main(void)
{
  log = fopen("/mmio-log", "a");
  if (!log)
    log = stdout;
  //write64(ppage + 0x3ff8, 0xffffffff);
  write64(ppage + 0x3fb0, 0);
  print("initialized%s\n", "");
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
    if ((esr & 0x0f8000000UL) != 0x090000000UL) {
      print("received brk esr %016lx at %016lx!\n", esr, elr);
      write64(ppage + 0x3fd0, success);
      asm volatile("dmb sy" : : : "memory");
      asm volatile("dsb sy");
      asm volatile("isb");
      write64(ppage + 0x3ff0, 0);
      continue;
    }
    if (esr == 0x9600004f) {
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
	print("interrupt event (unknown)%s\n", "");
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
	print("interrupt event %08lx\n", event);
	//write64_to_va(va, event, read64(ppage + 0x3fe8));
	continue;
      }
      unsigned insn = 0;

      print("esr %016lx elr %016lx far %016lx\n", esr, elr, far);
      do {
	unsigned long va = far;
	unsigned long off0 = (va >> (14 + 11 + 11)) & 2047;
	unsigned long off1 = (va >> (14 + 11)) & 2047;
	unsigned long off2 = (va >> (14)) & 2047;
	unsigned long level0 = read64(ppage + 0x3e08);
	if (!(read64(level0 + off0 * 8) & 1)) {
	  print("no level0! %016lx\n", far);
	  break;
	}
	unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
	if (!(read64(level1 + off1 * 8) & 1)) {
	  print("no level1! %016lx\n", far);
	  break;
	}
	unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
	if (!(read64(level2 + off2 * 8) & 1)) {
	  //print("esr %016lx elr %016lx\n", esr, elr);
	  unsigned long pa, va, action = 1;
#if 0
	  file *f = fopen("/mmio-map", "r");
	  while (fscanf(f, "%ld %ld %ld\n", &pa, &va, &action) == 3) {
	    if ((read64(level2 + off2 * 8) & 0xffffffc000) == pa) {
#endif
	      pa = (read64(level2 + off2 * 8) & 0xffffffc000);
	      if ((pa & 0xfffff0000) == 0x23d2b0000)
		action = 0;
	      va = far;
	      if (pa) {
	      success = true;
	      insn = insn_at_va(elr, read64(ppage + 0x3fe8));
	      if (false &&
		  simulate_insn(read64(ppage + 0x3fc8), insn, elr, far, pa,
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
		print("remapping page at %016lx %016lx after %08x, %08x, %08x at %016lx\n", pa, va,
		      insn, insn_at_va(elr, read64(ppage + 0x3fe8)),
		      insn_at_va(elr, read64(ppage + 0x3fe0)),
		      elr);
	      }
	      } else
		print("null pa for %016lx\n", va);
#if 0
	      goto close;
	    }
	  }
	  print("couldn't find mmio addr %016lx\n", far);
	close:
	  fclose (f);
#endif
	} else {
	  print("level2 valid at %016lx\n", far);
	}
	unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
      } while (0);
      if (!success) {
	//print("FAR %016lx ELR %016lx ESR %016lx \n", far, elr, esr);

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
