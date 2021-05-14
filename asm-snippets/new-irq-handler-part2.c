#define VPAGE ((volatile unsigned long *)(0xfffffff000000000))

long mmiotrace(unsigned long frame)
{
  unsigned long far;
  asm volatile("mrs %0, far_el2" : "=r" (far));
  unsigned long elr;
  asm volatile("mrs %0, elr_el2" : "=r" (elr));
  unsigned long esr;
  asm volatile("mrs %0, esr_el2" : "=r" (esr));
  unsigned long ttbr0_el0;
  asm volatile("mrs %0, ttbr0_el1" : "=r" (ttbr0_el0));
  unsigned long ttbr1_el0;
  asm volatile("mrs %0, ttbr1_el1" : "=r" (ttbr1_el0));

 again:
  *(VPAGE + (0x3fc8/8)) = frame;
  *(VPAGE + (0x3fd8/8)) = esr;
  *(VPAGE + (0x3fe0/8)) = ttbr0_el0;
  *(VPAGE + (0x3fe8/8)) = ttbr1_el0;
  *(VPAGE + (0x3ff8/8)) = elr;
  *(VPAGE + (0x3ff0/8)) = far;
  if (*(VPAGE + (0x3e00/8)) == 0)
    return 0;
  while (*(VPAGE + (0x3ff0/8)));
  elr = *(VPAGE + (0x3ff8/8));
  asm volatile("msr elr_el2, %0" : : "r" (elr));

  if (*(VPAGE + (0x3fb0/8)) != 0) {
    unsigned val = *(volatile unsigned *)(*(VPAGE + (0x3fb8/8)));
    *(*(unsigned long **)(VPAGE + (0x3fb0/8))) = val;
    *(VPAGE + 0x3fb8/8) = val;
    goto again;
  }

  long ret = (*(VPAGE + (0x3fd0/8))) != 0;
  if (ret) {
    asm volatile("tlbi alle1");
    asm volatile("tlbi alle2");
  }
  return ret;
}
