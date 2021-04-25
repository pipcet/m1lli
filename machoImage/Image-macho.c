#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char **argv)
{
  if (argc != 3) {
  error:
    fprintf(stderr, "usage: %s <Image> <macho>\n",
	    argv[0]);
    exit(1);
  }

  FILE *f = fopen(argv[1], "r");
  if (!f)
    goto error;

  fseek(f, 0, SEEK_END);
  size_t size = ftell(f);
  size += (1<<21) - 1;
  size &= (-1<<21);
  void *buf = malloc(16384 + size);
  if (!buf)
    goto error;

  memset(buf, 0, 16384 + size);

  struct macho_header {
    struct {
      uint32_t magic;
      uint32_t cputype;
      uint32_t cpusubtype;
      uint32_t filetype;
      uint32_t ncmds;
      uint32_t sizeofcmds;
      uint32_t flags;
      uint32_t reserved;
    } header;
    struct {
      uint32_t cmd;
      uint32_t cmdsize;
      char segname[16];
      uint64_t vmaddr;
      uint64_t vmsize;
      uint64_t fileoff;
      uint64_t filesize;
      uint32_t maxprot;
      uint32_t initprot;
      uint32_t nsects;
      uint32_t flags;
      struct {
	char sectname[16];
	char segname[16];
	uint64_t addr;
	uint64_t size;
	uint32_t offset;
	uint32_t align;
	uint32_t reloff;
	uint32_t nreloc;
	uint32_t flags;
	uint32_t reserved[3];
      } section;
    } segment;
    struct {
      uint32_t cmd;
      uint32_t cmdsize;
      uint32_t flavor;
      uint32_t count;
      uint64_t x[29];
      uint64_t fp;
      uint64_t lr;
      uint64_t sp;
      uint64_t pc;
      uint32_t cpsr;
      uint32_t _pad; /* or flags? */
    } thread;
  } *hdr = buf;
  memset(hdr, 0, sizeof *hdr);
  hdr->header.magic = 0xfeedfacf;
#define CPU_TYPE_ARM64  0x0100000c
#define CPU_SUBTYPE_ARM64 0x00000002
  hdr->header.cputype = CPU_TYPE_ARM64;
  hdr->header.cpusubtype = CPU_SUBTYPE_ARM64;
#define MH_KERNEL       12
  hdr->header.filetype = MH_KERNEL;
  hdr->header.ncmds = 2;
  hdr->header.sizeofcmds = sizeof(hdr->segment) + sizeof(hdr->thread);
#define MH_DYLDLINK     0x00000004
  hdr->header.flags = MH_DYLDLINK;

  sprintf(hdr->segment.segname, "__TEXT");
#define LC_SEGMENT_64   0x19
  hdr->segment.cmd = LC_SEGMENT_64;
  hdr->segment.cmdsize = sizeof(hdr->segment);
  hdr->segment.maxprot = 7;
  hdr->segment.maxprot = 7;
  hdr->segment.vmaddr = 0xffffe00000000000;
  hdr->segment.vmsize = size;
  hdr->segment.fileoff = 16384;
  hdr->segment.filesize = size;
  hdr->segment.maxprot = 7;
  hdr->segment.nsects = 1;
  sprintf(hdr->segment.section.sectname, "KERNEL");
  sprintf(hdr->segment.section.segname, "__TEXT");
  hdr->segment.section.addr = 0xffffe00000000000;
  hdr->segment.section.size = size;
  hdr->segment.section.offset = 16384;
#define LC_UNIXTHREAD   0x5
  hdr->thread.cmd = LC_UNIXTHREAD;
  hdr->thread.cmdsize = sizeof(hdr->thread);
#define ARM_THREAD_STATE64 6
  hdr->thread.flavor = ARM_THREAD_STATE64;
  hdr->thread.count = 68;
  hdr->thread.pc = 0xffffe00000000050;
  void *image = buf + 16384;
  fread(image, 16384 + size, 1, f);
  fclose(f);
  f = fopen(argv[2], "w");
  if (!f)
    goto error;
  fwrite(buf, 1, 16384 + size, f);
  return 0;
}
