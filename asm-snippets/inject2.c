void f() {
  asm volatile("add %0, ")
  asm volatile("msr s3_6_c15_c1_6, %0" : : "r" (0x2020a506f020f0e0L));
}
