#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ptstuff.h"

#include "../asm-snippets/new-irq-handler-part1..h"
#include "../asm-snippets/new-irq-handler-part2..h"
#include "../asm-snippets/infloop..h"
#include "../asm-snippets/irq-handler-store-ttbr..h"
#include "../asm-snippets/irq-handler-store-magic-cookie..h"
#include "../asm-snippets/new-vbar-entry..h"
#include "../asm-snippets/new-vbar-entry-special..h"
#include "../asm-snippets/new-vbar-entry-for-mrs..h"
#include "../asm-snippets/delay-loop..h"
#include "../asm-snippets/expose-ttbr..h"
#include "../asm-snippets/expose-ttbr-2..h"
#include "../asm-snippets/expose-ttbr-to-stack..h"
#include "../asm-snippets/wait-for-confirmation..h"
#include "../asm-snippets/wait-for-confirmation-receiver..h"
#include "../asm-snippets/wait-for-confirmation-receiver-part2..h"
#include "../asm-snippets/optimized-putc..h"

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
	f(pte2, offs_to_va(off0, off1, 0), 2, cookie);
	continue;
      }
      if (!(pte2 & 1))
	continue;
      unsigned long level2 = pte2 & 0xfffffff000;
      for (off2 = 0; off2 < 2048; off2++) {
	unsigned long pte3 = read64(level2 + off2 * 8);

	f(pte3, offs_to_va(off0, off1, off2), 3, cookie);
      }
    }
  }
}

void dump_pt_compressed(unsigned long level0)
{
  unsigned long seen_tags[16] = { 0, };
  void f(unsigned long pte, unsigned long va, int level, void *cookie)
  {
    unsigned long ptepa = pte & 0xfffffff000;
    unsigned long tags = pte &~ ptepa;
    int i;
    for (i = 0; i < 16; i++) {
      if (tags == seen_tags[i])
	return;
      if (!seen_tags[i])
	break;
    }
    if (i < 16)
      seen_tags[i] = tags;
    printf("%016llx %016llx %d\n", va, pte, level);
  }
  iterate_pt(level0, f, NULL);
}

void dump_pt(unsigned long level0)
{
  unsigned long seen_tags[16] = { 0, };
  void f(unsigned long pte, unsigned long va, int level, void *cookie)
  {
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
  iterate_pt(level0, f, NULL);
}

int main(int argc, char **argv)
{
  unsigned long addr = 0, addr2 = 0;
  unsigned long action;
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
  if (argv[2] && argv[3] && argv[4]) {
    action = strtoll(argv[4], NULL, 0);
  } else {
    action = 1;
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
    unsigned long base = read64(0xac0000008);
    unsigned long levels[] = {
      level0_ttbr(),
      read64(base + 0x3ad66e0),
      base + (0x806b98000 - 0x8030bc000)
    };
    for(int i = 0; i < ARRAYELTS(levels); i++) {
      unsigned long level0 = levels[i];
      unsigned long va = addr;
      unsigned long off0 = (addr >> (14 + 11 + 11)) & 2047;
      unsigned long off1 = (addr >> (14 + 11)) & 2047;
      unsigned long off2 = (addr >> (14)) & 2047;
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
    }
  } else if (strcmp(argv[1], "unmap-pa") == 0) {
    unsigned long base = read64(0xac0000008);
    unsigned long levels[] = {
      level0_ttbr(),
      //read64(base + 0x3ad66e0),
      //read64(base + 0x3ad66f0),
      //base + (0x806b98000 - 0x8030bc000), // diff 3adc000
      //base + (0x806b94000 - 0x8030bc000), // diff 3ad8000
    };
    for(int i = 0; i < ARRAYELTS(levels); i++) {
      unsigned long level0 = levels[i];
      unsigned long pa = addr;
      unsigned long off0, off1, off2;
      for (off0 = 0; off0 < 2048; off0++) {
	if (!(read64(level0 + off0 * 8) & 1))
	  continue;
	if ((read64(level0 + off0 * 8) & 3) == 1) {
	  fprintf(stderr, "block at %016lx\n", offs_to_va(off0, 0, 0));
	}
	unsigned long level1 = read64(level0 + off0 * 8) & 0xfffffff000;
	for (off1 = 0; off1 < 2048; off1++) {
	  if (!(read64(level1 + off1 * 8) & 1))
	    continue;
	  if ((read64(level1 + off1 * 8) & 3) == 1) {
	    if ((read64(level1 + off1 * 8) & 0xf00000000) == 0x200000000) {
	      write64(level1 + off1 * 8, read64(level1 + off1 * 8) &~ 1L);
	      fprintf(stderr, "unmapping block at %016lx %016lx\n",
		      offs_to_va(off0, off1, 0), read64(level1 + off1 * 8));
	      continue;
	    }
	    if ((read64(level1 + off1 * 8) & 0xf00000000) == 0xb00000000) {
	      write64(level1 + off1 * 8, read64(level1 + off1 * 8) &~ 1L);
	      fprintf(stderr, "unmapping block at %016lx %016lx\n",
		      offs_to_va(off0, off1, 0), read64(level1 + off1 * 8));
	      continue;
	    }
	  }
	  unsigned long level2 = read64(level1 + off1 * 8) & 0xfffffff000;
	  for (off2 = 0; off2 < 2048; off2++) {
	    static int count = 0;
	    if (!(read64(level2 + off2 * 8) & 1))
	      continue;

	    unsigned long pte = read64(level2 + off2 * 8) & 0xfffffff000;
	    if (pte >= pa && pte < addr2) {
	      if (count++ < 16) {
		printf("unmapping %016lx [%016lx] at %016lx\n",
		       pte, read64(level2 + off2 * 8), offs_to_va(off0, off1, off2));
	      }

	      FILE *f;
	      f = fopen("/mmio-map", "a");
	      if (f) {
		fprintf(f, "%ld %ld %ld\n", pte, offs_to_va(off0, off1, off2),
			action);
		fclose(f);
	      }
	      write64(level2 + off2 * 8, read64(level2 + off2 * 8) &~ 1L);
	    }
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
  } else if (strcmp(argv[1], "init3") == 0) {
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
#if 1
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
#if 0
    while (!read64(0xb90003e08) ||
	   (read64(0xb90003e08) & 255)) {
      if (read64(base + 0x3ad66f0) & 0x800000000) {
	write64(0xb90003e08, read64(base + 0x3ad66f0));
      }
    }
#endif
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
#if 0
    install_page(0xfffffff000000000, 0xb90000000, 0, base + (0x806b98000 - 0x8030bc000));
    install_page(0xfffffff800000000, 0xb90000000, 1, base + (0x806b98000 - 0x8030bc000));
    install_page(0xfffffff800004000, 0xb90004000, 1, base + (0x806b98000 - 0x8030bc000));
    install_page(0x0000000900000000, 0xb90000000, 1, base + (0x806b94000 - 0x8030bc000));
    install_page(0x0000000900004000, 0xb90004000, 1, base + (0x806b94000 - 0x8030bc000));
#endif
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
#if 0
    unsigned long offs2[] = {
      0x8000 - 0x2000, 0x8200 - 0x2000, 0x8400 - 0x2000,
      0x9000 - 0x2000, 0x9200 - 0x2000, 0x9400 - 0x2000,
      0x13ec000 - 0xc02000, 0x13ec200 - 0xc02000, 0x13ec400 - 0xc02000,
      0x13ec080 - 0xc02000, 0x13ec280 - 0xc02000, 0x13ec480 - 0xc02000,
      0x13ec100 - 0xc02000, 0x13ec300 - 0xc02000, 0x13ec500 - 0xc02000,
      0x13ec180 - 0xc02000, 0x13ec380 - 0xc02000, 0x13ec580 - 0xc02000,
    };
    for (int j = 0; j < ARRAYELTS(offs2); j++) {
      unsigned long off = offs2[j];
#if 0
      for (int i = 2; i < ARRAYELTS(expose_ttbr_to_stack); i++) {
	write32(base + 0xc02000 + off + 4 * i, expose_ttbr_to_stack[i]);
      }
      unsigned oldbr = read32(base + 0xc02000 + off);
      if (((oldbr & 0xff000000) == 0x14000000) && oldbr != 0x14000000)
	write32(base + 0xc02000 + off + 0x4, oldbr - 1);
      else
	write32(base + 0xc02000 + off + 0x4, oldbr);
#else
      for (int i = 0; i < ARRAYELTS(expose_ttbr_to_stack); i++) {
	write32(base + 0xc02000 + off + 4 * i, expose_ttbr_to_stack[i]);
      }
#endif
      write32(base + 0xc02000 + off + 0x38, off);

      write32(base + 0xc02000 + off, expose_ttbr_to_stack[0]);
    }
    write32(base + 0xc08ffc, 0x14000000);
    write32(base + 0xc09ffc, 0x14000000);
    write32(base + 0x13ecffc, 0x14000000);
#endif
    unsigned long offs[] = {
      0, 0x80, 0x200, 0x400,
      0x8000 - 0x2000, 0x8200 - 0x2000, 0x8400 - 0x2000,
      0x9000 - 0x2000, 0x9200 - 0x2000, 0x9400 - 0x2000,
      0x13ec000 - 0xc02000, 0x13ec200 - 0xc02000, 0x13ec400 - 0xc02000,
      0x13ec080 - 0xc02000, 0x13ec280 - 0xc02000, 0x13ec480 - 0xc02000,
      0x13ec100 - 0xc02000, 0x13ec300 - 0xc02000, 0x13ec500 - 0xc02000,
      0x13ec180 - 0xc02000, 0x13ec380 - 0xc02000, 0x13ec580 - 0xc02000,
    };
#if 1
    for (int j = 0; j < ARRAYELTS(offs); j++) {
      unsigned long off = offs[j];
      if (off < 0x13ec000 - 0xc02000) {
	for (int i = 0; i < ARRAYELTS(new_vbar_entry); i++) {
	  write32(base + 0xc02000 + off + 4 * i, new_vbar_entry[i]);
	}
      } else {
	for (int i = 0; i < ARRAYELTS(new_vbar_entry_special); i++) {
	  write32(base + 0xc02000 + off + 4 * i, new_vbar_entry_special[i]);
	}
      }
      unsigned oldbr = read32(base + 0xc02000 + off);
      if (((oldbr & 0xff000000) == 0x14000000) && oldbr != 0x14000000)
	write32(base + 0xc02000 + off + 0x4, oldbr - 1);
      else
	write32(base + 0xc02000 + off + 0x4, oldbr);
      //write32(base + 0xc02000 + off + 0x38, off);

      //write32(base + 0xc02000 + off, 0x1400001f);
      //write32(base + 0xc02000 + off + 31 * 4, 0x14000000);
      //write32(base + 0xc02000 + off, code3[0]);
    }
#endif
#endif
#if 0
    for (int i = 0; i < ARRAYELTS(new_vbar_entry_for_mrs); i++) {
      write32(base + 0xc09200 + i, new_vbar_entry_for_mrs[i]);
      write32(base + 0xc08200 + i, new_vbar_entry_for_mrs[i]);
    }
#endif
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
    install_page(0xfffffff000004000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
    printf("mapping page\n");
    install_page(0xfffffff000000000, 0xb90000000, PAGE_RW, read64(0xb90003e08));
    printf("mapping page\n");
    install_page(0xfffffff100000000, 0x23b100000, PAGE_RW, read64(0xb90003e08));
    printf("mapping page\n");
    install_page(0xfffffff100008000, 0x23d2b0000, PAGE_RW, read64(0xb90003e08));
    printf("mapping page\n");
    install_page(0xfffffff800000000, 0xb90000000, 1, read64(0xb90003e08));
    printf("mapping page\n");
    install_page(0xfffffff800004000, 0xb90004000, 1, read64(0xb90003e08));

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
      write32(base + 0xc02000 + off, code3[0]);
    }
    printf("done\n");
  } else {
    printf("unknown command %s\n", argv[1]);
  }

  return 0;
}
