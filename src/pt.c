#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ptstuff.h"

#include "../asm-snippets/new-irq-handler-part1..h"
#include "../asm-snippets/new-irq-handler-part2..h"
#include "../asm-snippets/irq-handler-store-ttbr..h"
#include "../asm-snippets/irq-handler-store-magic-cookie..h"
#include "../asm-snippets/new-vbar-entry..h"

unsigned long level0_ttbr(void)
{
  return read64(0xb90003e08);
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

int main(int argc, char **argv)
{
  unsigned long addr = 0, addr2 = 0;
  if (!argv[1])
    return 1;
  if (argv[2]) {
    addr = strtoll(argv[2], NULL, 0);
  }
  if (argv[2] && argv[3]) {
    addr2 = strtoll(argv[3], NULL, 0);
  } else {
    addr2 = addr + 16383;
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
	  if (pte >= pa && pte < addr2) {
	    printf("%016llx %016llx\n", offs_to_va(off0, off1, off2),
		   pte);
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
    if (!(read64(level0 + off0 * 8) & 1)) {
      printf("invalid level1 entry\n");
      return 1;
    }
    unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
    if (!(read64(level1 + off1 * 8) & 1)) {
      printf("invalid level2 entry\n");
      return 1;
    }
    unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
    if (!(read64(level2 + off2 * 8) & 1)) {
      printf("invalid level3 entry\n");
      return 1;
    }
    if ((read64(level1 + off1 * 8) & 3) == 1) {
      printf("%016lx %016lx [block]\n", level2, read64(level1 + off1 * 8));
    }
    unsigned long level3 = read64(level2 + off2 * 8) & 0xfffffff000;
    printf("%016lx %016lx\n", level3, read64(level2 + off2 * 8));
  } else if (strcmp(argv[1], "map-va-to-pa-rw") == 0) {
  } else if (strcmp(argv[1], "map-va-to-pa-rx") == 0) {
  } else if (strcmp(argv[1], "unmap-va") == 0) {
    unsigned long va = addr;
    unsigned long off0 = (addr >> (14 + 11 + 11)) & 2047;
    unsigned long off1 = (addr >> (14 + 11)) & 2047;
    unsigned long off2 = (addr >> (14)) & 2047;
    unsigned long level0 = level0_ttbr();
    if (!(read64(level0 + off0 * 8) & 1))
      return 1;
    unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
    if (!(read64(level1 + off1 * 8) & 1))
      return 1;
    unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
    if (!(read64(level2 + off2 * 8) & 1))
      return 1;
    write64(level2 + off2 * 8, read64(level2 + off2 * 8) &~ 1L);
    printf("unmapped %016lx\n", va);
  } else if (strcmp(argv[1], "unmap-pa") == 0) {
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
	  if (pte >= pa && pte < addr2) {
	    printf("unmapping %016lx [%016lx] at %016lx\n",
		   pte, read64(level2 + off2 * 8), offs_to_va(off0, off1, off2));
	    FILE *f;
	    f = fopen("/mmio-map", "a");
	    if (f) {
	      fprintf(f, "%ld %ld\n", pte, offs_to_va(off0, off1, off2));
	      fclose(f);
	    }
	    write64(level2 + off2 * 8, read64(level2 + off2 * 8) &~ 1L);
	  }
	}
      }
    }
  } else if (strcmp(argv[1], "remap-pa") == 0) {
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
	  if ((read64(level2 + off2 * 8) & 1))
	    continue;

	  unsigned long pte = read64(level2 + off2 * 8) & 0xfffffff000;
	  if (pte >= pa && pte < addr2) {
	    printf("remapping %016lx at %016lx\n",
		   read64(level2 + off2 * 8), offs_to_va(off0, off1, off2));
	    write64(level2 + off2 * 8, read64(level2 + off2 * 8) | 1L);
	  }
	}
      }
    }
  } else if (strcmp(argv[1], "init") == 0) {
    printf("initializing\n");
    unsigned long offs[] = { 0, /* 0x80, */ 0x200, /* 0x400, */ 							    0x9000 - 0x2000, 0x9200 - 0x2000, 0x9400 - 0x2000 };
    unsigned long base = read64(0xac0000008); /* MAGIC address */
    printf("base at %016lx, VBAR=%016lx\n", base, base + 0xc02000);
#define code1 irq_handler_store_magic_cookie
    /* code1 should be [0xa9bf07e0,0xd11003e0,0x9272c400,0x58000121,0xf9000001,0xd5382001,0xa94007e0,0x910043ff,0x1400041c,0xd503201f,0xd503201f,0xd503201f,0x7b5a3da3,0x2ff2a7a3] */
    for (int i = ARRAYELTS(code1) - 1; i > 0; i--)
      write32(base + 0xc02080 + 4 * i, code1[i]);
    unsigned long stackbase = 0;
    write32(base + 0xc02080, code1[0]);

    while (stackbase == 0) {
      write32(base + 0xc02080, code1[0]);
      printf("waiting for first IRQ\n");
      write32(base + 0xc02080, code1[0]);
      for (unsigned long offset = 0x800000000; offset < 0x900000000; offset += 16384) {
	unsigned long val = read64(offset);
	/* Just a random tag, so we find the right page without knowing its PA. */
	if (val == 0x2ff2a7a37b5a3da3) {
	  stackbase = offset;
	  break;
	}
      }
    }
    /* The branch that used to be there. */
    write32(base + 0xc02080, 0x14000424);
    printf("received first IRQ: stackbase %016lx\n", stackbase);


#define code2 irq_handler_store_ttbr
    /* code2 should be [0xa9bf07e0,0xd11003e0,0x9272c400,0x58000121,0xd53c2021, 0xf9000001,0xa94007e0,0x910043ff,0x1400041c,0xd503201f,0xd503201f,0xd503201f,0x00000000,0x0000000b] */
    for (int i = ARRAYELTS(code2) - 1; i > 0; i--)
      write32(base + 0xc02080 + 4 * i, code2[i]);
    write32(base + 0xc02080, code2[0]);

    printf("waiting for IRQ\n");
    while (read64(stackbase) == 0x2ff2a7a37b5a3da3);
    unsigned long level0 = read64(stackbase);
    printf("received second IRQ\n");
    write32(base + 0xc02080, 0x14000424);

    printf("TTBR at %016lx\n", level0);

    /* The branch that used to be there. */

    write64(0xb90003e08, level0);
    write64(0xb90003e10, 0xb90004000);

    printf("mapping page\n");
    install_page(0xfffffff000004000, 0x23b100000, 2);
    printf("mapping page\n");
    install_page(0xfffffff000000000, 0xb90000000, 0);
    printf("mapping page\n");
    install_page(0xfffffff100000000, 0x23b100000, 2);
    printf("mapping page\n");
    install_page(0xfffffff100008000, 0x23d2b0000, 2);
    printf("mapping page\n");
    install_page(0xfffffff800000000, 0xb90000000, 1);

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
    for (int j = 0; j < ARRAYELTS(offs); j++) {
      unsigned long off = offs[j];
#define code3 new_vbar_entry
      /* code3 should be [0x14000002,0x14000423,0xa9bf07e0,0xa9bf7bfd,0x58000100,0x58000121,0xd63f0000,0xa9407bfd,0xa94107e0,0x910083ff,0x17fffff7,0xd65f03c0,0x00000000,0xfffffff8,0x00000000,0x00000000] */
      for (int i = 2; i < ARRAYELTS(code3); i++) {
	write32(base + 0xc02000 + off + 4 * i, code3[i]);
      }
      unsigned oldbr = read32(base + 0xc02000 + off);
      if ((oldbr & 0xff000000) == 0x14000000)
	write32(base + 0xc02000 + off + 0x4, oldbr - 1);
      write32(base + 0xc02000 + off + 0x38, off);

      write32(base + 0xc02000 + off, code3[0]);
    }
    printf("done\n");
  } else {
    printf("unknown command %s\n", argv[1]);
  }

  return 0;
}
