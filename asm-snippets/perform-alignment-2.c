void perform_alignment(void) __attribute__((section(".text")));

void perform_alignment(void)
{
  unsigned long pc;
  asm volatile("adr %0, perform_alignment" : "=r" (pc));
  unsigned long page = pc & ~16383;
  unsigned long newpage = (page + (1 << 21) - 1) & -(1 << 21);
  if (page != newpage) {
    unsigned long size = ((unsigned long *)page)[2];
    char *p = (char *)page + size;
    while (p-- != (char *)page)
      p[newpage - page] = *p;
    asm volatile("br %0" : : "r" (newpage + pc - page));
  }
}
