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
asm(".quad 32 * 1024 * 1024\n\t");
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
asm("argdummy:\n\t.quad 0\n");
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
asm("nop");
asm("nop");
asm(".rept 8192\n\t.quad 0\n\t.endr\n\tstack:\n\t");


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

void boot_macho_init(unsigned long long *arg, unsigned long ptr)
{
#if 0
  volatile unsigned *volatile framebuffer = (void *)0xbdf438000;
  for (unsigned x = 0; x < 2560; x++) {
    for (unsigned y = 0; y < 800; y++) {
      framebuffer[y * 2560 + x] = ((*arg)&(1 << (x & 31))) ? 0xffffff : 0;
    }
  }
#endif
  top_of_mem = (void *)0x800000000 + 1024 * 1024 * 1024;
  void *start = ((void *)arg) - 0x48 + 256 * 1024;
  struct macho_header *header = start;
    struct macho_command *command = (void *)(header + 1);
    struct macho_command *last_command = (void *)command + header->cmdsize;
    u64 pc = 0;
    u64 vmbase = 0;
    u64 vmtotalsize = 0;
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
    void *dest = memalign(0x10000, vmtotalsize);
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
                    }
                }
            }
        }
        command = (void *)command + command->size;
    }
    ((void (*)(unsigned long))virtpc)(ptr);
}

asm("nop\n\t");
asm("nop\n\t");
asm("nop\n\t");
asm("nop\n\t");
asm("nop\n\t");
asm("nop\n\t");

char buf[127380] = { 1, };
