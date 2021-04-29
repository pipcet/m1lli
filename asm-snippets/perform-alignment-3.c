void perform_alignment(void) __attribute__((section(".noinclude.text")));

typedef void (*fptr)(void) __attribute__((noreturn));

void perform_alignment(void)
{
  asm volatile(".pushsection .text");
  asm volatile(".cfi_startproc");
  unsigned long pc;
  asm volatile("adr %0, ." : "=r" (pc));
  unsigned long page = pc & ~16383;
  unsigned long newpage = (page + (1 << 21) - 1) & -(1 << 21);
  if (page != newpage) {
    unsigned long size = ((unsigned long *)page)[2];
    __int128 *p = (void *)page + size;
    while (p != (__int128 *)page) {
      p[(newpage - page)/16] = *p; p--;
    }
    asm volatile("br %0" : : "r" (newpage + pc - page));
    __builtin_unreachable();
  }
  asm volatile(".cfi_endproc");
  asm volatile(".popsection");
  asm volatile("");
  return;
}
