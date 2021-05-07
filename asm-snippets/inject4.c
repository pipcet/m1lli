void f(void)
{
  return;
  unsigned *vbar;
  unsigned *shadow_vbar = (unsigned *)0xa0000000;
  asm volatile("mrs %0, vbar_el1" : "=r" (vbar));
  for (volatile unsigned *vbarp = vbar; vbarp < vbar + 32 * 16; vbarp += 32) {
    for (int i = 0; i < 32; i++)
      shadow_vbar[i] = vbarp[i];
    vbarp[31] = 0x17ffffe1;
    vbarp[30] = 0x910043ff;
    vbarp[29] = 0xa9407be0;
    shadow_vbar += 32;
  }
  *(volatile unsigned **)0xa00004000 = vbar;
  //asm volatile("msr vbar_el1, %0" : : "r" (0xa00000000));
}
