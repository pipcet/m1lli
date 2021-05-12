#define VPAGE ((volatile unsigned long *)(0xfffffff000000000))

int mmiotrace(void)
{
  unsigned long far;
  asm volatile("mrs %0, far_el1" : "=r" (far));
  unsigned long elr;
  asm volatile("mrs %0, elr_el1" : "=r" (elr));

  *(VPAGE + 0x3ff0/8) = far;
  *(VPAGE + 0x3ff8/8) = elr;
  while (*(VPAGE + 0x3ff0/8));
  return (*(VPAGE + 0x3ff8/8)) != 0;
}
