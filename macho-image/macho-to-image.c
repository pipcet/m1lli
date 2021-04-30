#define MACHO_COMMAND_UNIX_THREAD 0x05
#define MACHO_COMMAND_SEGMENT_64  0x19

typedef unsigned long long u64;
typedef u64 size_t;
typedef unsigned int u32;

#ifndef KERNEL_SIZE
#define KERNEL_SIZE 32 * 1024 * 1024
#endif

#define NULL ((void *)0)

struct macho_header {
    u32 irrelevant[5];
    u32 cmdsize;
    u32 irrelevant2[2];
};

struct macho_command {
    u32 type;
    u32 size;
    union {
        struct {
            u32 thread_type;
            u32 length;
            u64 regs[32];
            u64 pc;
            u64 regs2[1];
        } unix_thread;
        struct {
            char segname[16];
            u64 vmaddr;
            u64 vmsize;
            u64 fileoff;
            u64 filesize;
            u64 unused2[2];
        } segment_64;
    } u;
};

asm(".text\n\t");
asm("nop\n\t");
asm("b primary_entry\n\t");
asm(".quad 0\n\t");
#define STR(x) #x
asm(".quad 256 * 1024 * 1024\n\t");
asm(".quad 0\n\t");
asm(".quad 0\n\t");
asm(".quad 0\n\t");
asm(".quad 0\n\t");
asm(".ascii \"ARMd\"\n\t");
asm(".long 0\n");
asm("primary_entry:\n\t");
asm("nop\n\t");
asm("b 1f\n\t");
asm(".globl argdummy\n\t");
asm("argdummy:\n\t.quad 0x806640000\n");
asm("adr x1, argdummy\n\t");
asm("str x0, [x1]");
asm("1:\n\t");
asm("adr x1, stack\n\t");
asm("sub x1, x1, #16\n\t");
asm("mov x0, x1\n\t");
asm("mov sp, x0\n\t");
asm("bl 1f\n\t");
asm("1:\n\t");
asm("mov x1, #0xbd\n\t");
asm("lsl x1, x1, #12\n\t");
asm("add x1, x1, #0xf44\n\t");
asm("lsl x1, x1, #16\n\t");
asm("add x1, x1, #0x8000\n\t");
asm("mov w0, #0xff00\n\t");
asm("0: str w0, [x1, #0x00]\n\t");
asm("str w0, [x1, #0x04]\n\t");
asm("str w0, [x1, #0x08]\n\t");
asm("str w0, [x1, #0x0c]\n\t");
asm("add x1, x1, #16\n\t");
asm("mov x1, #0xbe\n\t");
asm("lsl x1, x1, #12\n\t");
asm("add x1, x1, #0x03d\n\t");
asm("lsl x1, x1, #16\n\t");
asm("add x1, x1, #0x8000\n\t");
asm("mov sp, x1\n\t");
asm("adr x0, argdummy\n\t");
asm("ldr x1, [x0]");
asm("bl boot_macho_init\n\t");
asm("nop");

asm(".p2align 7\n\t"
    "smpentry:\n\t"
    "adr x1, rvbar\n\t"
    "add x1, x1, :lo12:rvbar\n\t"
    "ldr x1, [x1]\n\t"
    "br x1\n\t"
    ".p2align 7\n\t"
    "rvbar:\n\t"
    ".quad 0\n\t"
    "end_smpentry:\n\t"
    ".p2align 7\n\t"
    "upentry:\n\t"
#if 0
    "adrp x1, upentry\n\t"
    "add x1, x1, :lo12:upentry\n\t"
    "add x2, x1, #-2048\n\t"
    "mov x4, #256\n\t"
    "0:\n\t"
    "ldr x3, [x2]\n\t"
    "str x3, [x1]\n\t"
    "add x1, x1, 8\n\t"
    "add x2, x2, 8\n\t"
    "add x4, x4, -1\n\t"
    "cbnz x4, 0b\n\t"
#endif
    "adr x1, smpentry\n\t"
    "add x1, x1, #0x2000\n\t"
    "add x1, x1, -0x104\n\t"
    "br x1\n\t"
    "end_upentry:");
asm(".rept 8192\n\t.quad 0\n\t.endr\n\tstack:\n\t");
asm(".p2align 12\n\t.rept 0xe38\n\t.byte 0\n\t.endr");
asm("fdt: .rept 0x1c4\n\t.ascii \"x\"\n\t.endr\n\tadr x0, fdt");

asm("counter_start: nop\n\t");
asm("adr x0, counter");
asm("ldr x1, [x0]");
asm("add x1, x1, 1");
asm("str x1, [x0]");
asm("b counter_start");
asm("counter: .quad 0");

asm("mov x0, #0\n\t");
asm("orr x0, x0, 1\n\t");
asm("lsl x0, x0, 1\n\t");
asm("br x0");

extern char argdummy[1];
extern char start[1];
register  void *top_of_mem __asm__("x24");

void *memset(void *p, int c, size_t size)
{
  char *p2 = p;
  while (size--) *p2++ = c;
  return p;
}

void *memalign(size_t align, size_t size)
{
  while (((size_t)top_of_mem) & (align - 1))
    top_of_mem++;

  void *ret = top_of_mem;
  top_of_mem += size;
  return ret;
}

unsigned int bswap(unsigned int x)
{
  return __builtin_bswap32(x);
}

unsigned long bswap64(unsigned long x)
{
  return __builtin_bswap64(x);
}

#define fdt32(x) bswap(x)
#define fdt64(x) bswap((x) >> 32), bswap((x) & 0xffffffff)

inline void build_dt(unsigned int *dt, unsigned long memoff0,
		     unsigned long memsize0)
{
  /* echo '/dts-v1/; / { #address-cells=<2>; #size-cells=<2>; memory { reg = <0x12345678 0x9abcdef0 0x0fedcba9 0x87654321>;};};' | dtc -I dts -O dtb | od -tx4 --width=1 -Anone -v | sed -e 's/ \(.*\)/\tfdt32(0x\1),/' */
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

  __builtin_memcpy(dt, templ, sizeof(templ));
}

void mangle_x0(unsigned long x0, unsigned long x1)
{
  void *buf = x1;
}

asm("nop\n\tnop\n\tmov x0, #0\n\tb .\n\t");


void boot_macho_init(unsigned long long *arg, unsigned long ptr)
{
#if 0
  unsigned * framebuffer = (void *)0xbdf438000;
  for (unsigned x = 0; x < 2560; x++) {
    for (unsigned y = 0; y < 800; y++) {
      framebuffer[y * 2560 + x] = y; //((*arg)&(1 << (x & 31))) ? 0xffffff : 0;
    }
  }
#endif
  top_of_mem = (void *)0x800000000 + 1024 * 1024 * 1024;
  unsigned long *rvbar = (void *)arg - 0x48 - 0x4000 + 0x80;
  void *start = ((void *)arg) - 0x48 + 128 * 1024;
  while (*(unsigned *)start != 0xfeedfacf)
      start += 4;
  struct macho_header *header = start;
  struct macho_command *command = (void *)(header + 1);
  struct macho_command *last_command = (void *)command + header->cmdsize;
  u64 pc = 0;
  u64 vmbase = 0;
  u64 vmtotalsize = 0;
  u64 dtsize = 2 * 1024 * 1024;
  while (command < last_command) {
      switch (command->type) {
	  case MACHO_COMMAND_UNIX_THREAD:
	      pc = command->u.unix_thread.pc;
	      break;
	  case MACHO_COMMAND_SEGMENT_64: {
	      u64 vmaddr = command->u.segment_64.vmaddr;
	      u64 vmsize = command->u.segment_64.vmsize;

	      if (vmbase == 0)
		  vmbase = vmaddr;
	      if (vmsize + vmbase - vmaddr > vmtotalsize)
		  vmtotalsize = vmsize + vmaddr - vmbase;
                break;
            }
        }
        command = (void *)command + command->size;
  }
  vmtotalsize += 16383;
  vmtotalsize &= -16384L;
  void *dest = memalign(1 << 21, vmtotalsize + dtsize);
  void *dt = dest + vmtotalsize;
  *(unsigned int *)dt = 0;
  *((unsigned int *)dt + 1) = dtsize;
  *((unsigned long *)dt + 1) = ptr;
  for (size_t count = 0; count < vmtotalsize; count++)
    ((char*)dest)[count] = 0;
    command = (void *)(header + 1);
    void *virtpc = NULL;
    while (command < last_command) {
        switch (command->type) {
            case MACHO_COMMAND_SEGMENT_64: {
                if (vmbase == 0)
                    vmbase = command->u.segment_64.vmaddr;
                u64 vmaddr = command->u.segment_64.vmaddr;
                u64 vmsize = command->u.segment_64.vmsize;
                u64 fileoff = command->u.segment_64.fileoff;
                u64 filesize = command->u.segment_64.filesize;
                u64 pcoff = pc - vmaddr;

		for (size_t count = 0; count < filesize; count++)
		    ((char*)dest)[vmaddr - vmbase + count] =
		        ((char *)start)[fileoff + count];
                if (pcoff < vmsize) {
                    if (pcoff < filesize) {
                        virtpc = dest + vmaddr - vmbase + pcoff;
			*rvbar = virtpc - 0x100;
                    }
                }
            }
        }
        command = (void *)command + command->size;
    }
    ((void (*)(unsigned long))virtpc)((unsigned long)dt);
}

asm("nop\n\t");
asm("nop\n\t");
asm("nop\n\t");
asm("nop\n\t");
asm("nop\n\t");
asm("nop\n\t");

char buf[118808] = { 1, };

int main(int argc, char **argv)
{
  const size_t prelude_size = PRELUDE_SIZE;
  if (argc != 3) {
  error:
    fprintf(stderr, "usage: %s <macho image> <Linux image>\n",
	    argv[0]);
    exit(1);
  }
}
