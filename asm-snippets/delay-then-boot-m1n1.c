void delay_then_boot_mini(unsigned long x0)
{
  void (*m1n1)(unsigned long) = (void *)0x900000000 + 0x4800;
  register unsigned long count = 1L << 34;
  while (--count)
    asm volatile("" : "=r" (count) : "r" (count));
  m1n1(x0);
}
