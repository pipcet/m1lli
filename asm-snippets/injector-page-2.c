unsigned long level0;

static inline unsigned long read_phys(unsigned long addr)
{
  return *(volatile unsigned long *)(addr | 0xfffffff000000000);
}

static inline void write_phys(unsigned long addr,
			      unsigned long val)
{
  *(volatile unsigned long *)(addr | 0xfffffff000000000) = val;
}

void find_page_mapping(unsigned long va)
{
  unsigned off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned off1 = (va >> (14 + 11)) & 2047;
  unsigned off2 = (va >> 14) & 2047;

  unsigned long level1 = read_phys(level0 + off0 * 8);
  level1 &= 0xfffffff000;
  unsigned long level2 = read_phys(level1 + off1 * 8);
  level2 &= 0xfffffff000;
  write_phys(level2 + off1 * 8, read_phys(level2 + off1 * 8) | 3);
}

void remap_page(unsigned long va)
{
  unsigned off0 = (va >> (14 + 11 + 11)) & 2047;
  unsigned off1 = (va >> (14 + 11)) & 2047;
  unsigned off2 = (va >> 14) & 2047;

  unsigned long level1 = read_phys(level0 + off0 * 8);
  level1 &= 0xfffffff000;
  unsigned long level2 = read_phys(level1 + off1 * 8);
  level2 &= 0xfffffff000;
  write_phys(level2 + off1 * 8, read_phys(level2 + off1 * 8) | 3);
}

void handle_exception(void)
{
  unsigned long esr_el2;
  asm volatile("mrs %0, esr_el2" : "=r" (esr_el2));
  unsigned ec = (esr_el2 >> 26) & 0x3f;
  if (ec == 0x21 || ec == 0x20 ||
      ec == 0x24 || ec == 0x25) {
    unsigned long far;
    unsigned long elr;
    asm volatile("mrs %0, far_el2" : "=r" (far));
    asm volatile("mrs %0, elr_el2" : "=r" (elr));
    remap_page(far &~ 0xfffL);
  }
}
