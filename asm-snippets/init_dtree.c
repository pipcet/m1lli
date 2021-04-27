#include <stddef.h>
#include <stdint.h>

asm("bl init_dtree\n\t");
asm("b end");
void init_dtree(unsigned long addr, unsigned long bootargs)
  __attribute__((section(".text")));

#define fdt32(x) bswap(x)
#define fdt64(x) bswap((x) >> 32), bswap((x) & 0xffffffff)

unsigned int bswap(unsigned int x)
{
  return __builtin_bswap32(x);
}

unsigned long bswap64(unsigned long x)
{
  return __builtin_bswap64(x);
}

void slow_memmove(void *dest, void *src, size_t count)
{
  volatile char *d = dest;
  volatile char *s = src;
  while (count--)
    *d++ = *s++;
}

void init_dtree(unsigned long addr, unsigned long bootargs)
{
  unsigned long memsize0 = 0;
  unsigned long memoff0 = 0;
  void *dt = (void *)addr;
  unsigned int templ[] = {
	fdt32(0xedfe0dd0),
	fdt32(0xb3000000),
	fdt32(0x38000000),
	fdt32(0x94000000),
	fdt32(0x28000000),
	fdt32(0x11000000),
	fdt32(0x10000000),
	fdt32(0x00000000),
	fdt32(0x1f000000),
	fdt32(0x5c000000),
	fdt32(0x00000000),
	fdt32(0x00000000),
	fdt32(0x00000000),
	fdt32(0x00000000),
	fdt32(0x01000000),
	fdt32(0x00000000),
	fdt32(0x03000000),
	fdt32(0x04000000),
	fdt32(0x00000000),
	fdt32(0x02000000),
	fdt32(0x03000000),
	fdt32(0x04000000),
	fdt32(0x0f000000),
	fdt32(0x02000000),
	fdt32(0x01000000),
	fdt32(0x6f6d656d),
	fdt32(0x00007972),
	fdt32(0x03000000),
	fdt32(0x10000000),
	fdt32(0x1b000000),
	fdt64(memoff0),
	fdt64(memsize0),
	fdt32(0x02000000),
	fdt32(0x02000000),
	fdt32(0x09000000),
	fdt32(0x64646123),
	fdt32(0x73736572),
	fdt32(0x6c65632d),
	fdt32(0x2300736c),
	fdt32(0x657a6973),
	fdt32(0x6c65632d),
	fdt32(0x7200736c),
	fdt32(0x00006765),
  };

  slow_memmove(dt, templ, sizeof(templ));
}
asm("end:");
