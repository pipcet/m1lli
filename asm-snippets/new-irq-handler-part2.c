#define VPAGE ((volatile unsigned long *)(0xfffffff000000000))

long mmiotrace(unsigned long frame)
{
  if (*(VPAGE + (0x3e00/8)) == 0)
    return 0;
  unsigned long off = *(unsigned long *)(frame + 33 * 8);
  *(VPAGE + (0x3fa0/8)) = *(unsigned long *)(frame + 32 * 8);
  *(VPAGE + (0x3fa8/8)) = *(unsigned long *)(frame + 33 * 8);
  unsigned long esr;
  //if ((esr & 0xe8000000) != 0x80000000)
  //  return 0;
  unsigned long far;
  unsigned long elr;
  unsigned long ttbr0;
  unsigned long ttbr1;
  unsigned long spsr;
  if (off >= 0x13ec000) {
    asm volatile("mrs %0, s3_6_c15_c10_5" : "=r" (esr));
    asm volatile("mrs %0, s3_6_c15_c10_7" : "=r" (far));
    asm volatile("mrs %0, s3_6_c15_c10_6" : "=r" (elr));
    asm volatile("mrs %0, ttbr0_el2" : "=r" (ttbr0));
    asm volatile("mrs %0, ttbr1_el2" : "=r" (ttbr1));
    asm volatile("mrs %0, s3_6_c15_c10_3" : "=r" (spsr));
  } else {
    asm volatile("mrs %0, esr_el1" : "=r" (esr));
    asm volatile("mrs %0, far_el2" : "=r" (far));
    asm volatile("mrs %0, elr_el2" : "=r" (elr));
    asm volatile("mrs %0, ttbr0_el1" : "=r" (ttbr0));
    asm volatile("mrs %0, ttbr1_el1" : "=r" (ttbr1));
  }

  *(VPAGE + (0x3fc8/8)) = frame;
  *(VPAGE + (0x3fd8/8)) = esr;
  *(VPAGE + (0x3fe0/8)) = ttbr0;
  *(VPAGE + (0x3fe8/8)) = ttbr1;
  *(VPAGE + (0x3ff8/8)) = elr;
  asm volatile("mrs %0, elr_el2" : "=r" (*(VPAGE + (0x3e10/8))));
  asm volatile("dmb sy" : : : "memory");
  asm volatile("dsb sy");
  asm volatile("isb");
  *(VPAGE + (0x3ff0/8)) = far;
  asm volatile("dmb sy" : : : "memory");
  asm volatile("dsb sy");
  asm volatile("isb");
  while (*(VPAGE + (0x3ff0/8))) {
    asm volatile("dmb sy" : : : "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
  }
  asm volatile("dmb sy" : : : "memory");
  asm volatile("dsb sy");
  asm volatile("isb");
  elr = *(VPAGE + (0x3ff8/8));
  if (off >= 0x13ec000) {
    //asm volatile("msr elr_el2, %0" : : "r" (elr));
    unsigned long tmp;
    asm volatile("mrs %0, s3_6_c15_c10_4" : "=r" (tmp));
    //tmp &= ~1L;
    asm volatile("msr s3_6_c15_c10_4, %0" : : "r" (tmp));
    asm volatile("mrs %0, s3_6_c15_c10_3" : "=r" (tmp));
    //tmp |= 0x200000;
    asm volatile("msr s3_6_c15_c10_3, %0" : : "r" (tmp));
    asm volatile("msr s3_6_c15_c10_6, %0" : : "r" (elr));
  } else {
    asm volatile("msr elr_el2, %0" : : "r" (elr));
  }

  if (0) if (*(VPAGE + (0x3fb0/8)) != 0) {
    asm volatile("dmb sy" : : : "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    volatile unsigned long *p = (void *)*(VPAGE + (0x3fb0/8));
    asm volatile("tlbi alle1");
    asm volatile("tlbi alle2");
    asm volatile("dmb sy" : : : "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    unsigned val = *(volatile unsigned *)(far);
    *(VPAGE + (0x3fb8/8)) = val;
    *(VPAGE + (0x3ff0/8)) = far;
    asm volatile("dmb sy" : : : "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    //*(VPAGE + (0x3fb0/8)) = 0;
    asm volatile("dmb sy" : : : "memory");
    asm volatile("dsb sy");
    asm volatile("isb");
    while (*(VPAGE + (0x3ff0/8)));
    *p = val;
    elr += 4;
    asm volatile("msr elr_el2, %0" : : "r" (elr));
  }
#if 0
  if (*(volatile unsigned*)0xfffffff10000800c == 3)
    *(volatile unsigned *)0xfffffff10000800c = 3;
#endif

  long ret = (*(VPAGE + (0x3fd0/8))) != 0;
  asm volatile("tlbi alle1");
  asm volatile("tlbi alle2");
  return ret ? ((off >= 0x13ec000) ? 2 : 1) : 0;
}
