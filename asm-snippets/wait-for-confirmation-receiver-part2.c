#define VPAGE ((volatile unsigned long *)(0xfffffff000000000))

unsigned long tables_changed(unsigned long ret)
{
  //if (*(VPAGE + (0x3e00/8)) == 0)
  //  return;
  (*(VPAGE + (0x3f00/8))) = 1;
  while (*(VPAGE + (0x3f00/8))) {
    asm volatile("isb");
    asm volatile("dsb sy");
    asm volatile("dmb sy");
  }
  return ret;
}
