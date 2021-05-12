void f(void) {
  asm volatile("b .");
  asm volatile("");
  asm volatile("msr s3_6_c15_c1_6, %0" : : "r" (0x2020a505f020f0f0L));
}
