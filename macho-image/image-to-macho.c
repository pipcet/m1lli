#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* these strange includes are precompiled assembly snippets included
   as binary code in the (native) binaries. */

static
#include "../asm-snippets/mov-x0-0..h"

static
#include "../asm-snippets/remap-to-physical..h"

static
#include "../asm-snippets/perform-alignment-4..h"

static
#include "../asm-snippets/jump-to-start-of-page..h"

static
#include "../asm-snippets/bring-up-phys..h"

static
#include "../asm-snippets/bring-up-phys-2..h"

static
#include "../asm-snippets/enable-all-clocks..h"

static
#include "../asm-snippets/x8r8g8b8..h"

static
#include "../asm-snippets/reboot-physical..h"

static
#include "../asm-snippets/reboot-physical-2..h"

static
#include "../asm-snippets/fillrect..h"

static
#include "../asm-snippets/save-boot-args..h"

static
#include "../asm-snippets/restore-boot-args..h"

static
#include "../asm-snippets/nop..h"

#define PRELUDE_SIZE 16384
#define IMAGE_PADDING (1 << 21)
#define VIRT_BASE 0xfffffe0007000000
#define HDR_SIZE 0x2000

int main(int argc, char **argv)
{
  const size_t prelude_size = PRELUDE_SIZE;
  if (argc != 3) {
  error:
    fprintf(stderr, "usage: %s <Linux image> <macho>\n",
	    argv[0]);
    exit(1);
  }

  FILE *f = fopen(argv[1], "r");
  if (!f)
    goto error;

  fseek(f, 0, SEEK_END);
  size_t image_size = ftell(f);
  fseek(f, 0, SEEK_SET);
  image_size += IMAGE_PADDING - 1;
  image_size &= -IMAGE_PADDING;
  void *buf = malloc(prelude_size + image_size);
  if (!buf)
    goto error;

  memset(buf, 0, prelude_size + image_size);

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
	uint32_t alignment_hint; /* just a hint, doesn't go up to 2 MiB */
	uint32_t reloff;
	uint32_t nreloc;
	uint32_t flags;
	uint32_t reserved[3];
      } section;
    } header_segment;
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
	uint32_t alignment_hint;
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
  hdr->header.ncmds = 3;
  hdr->header.sizeofcmds = sizeof(hdr->header_segment) + sizeof(hdr->segment) + sizeof(hdr->thread);
#define MH_DYLDLINK     0x00000004
  hdr->header.flags = MH_DYLDLINK;

#define LC_SEGMENT_64   0x19
  sprintf(hdr->header_segment.segname, "__HEADER");
  hdr->header_segment.cmd = LC_SEGMENT_64;
  hdr->header_segment.cmdsize = sizeof(hdr->header_segment);
  hdr->header_segment.maxprot = 1;
  hdr->header_segment.initprot = 1;
  hdr->header_segment.vmaddr = VIRT_BASE - prelude_size;
  hdr->header_segment.vmsize = prelude_size;
  hdr->header_segment.fileoff = 0;
  hdr->header_segment.filesize = prelude_size;
  hdr->header_segment.nsects = 1;
  sprintf(hdr->header_segment.section.sectname, "__header");
  sprintf(hdr->header_segment.section.segname, "__HEADER");
  hdr->header_segment.section.addr = VIRT_BASE - prelude_size;
  hdr->header_segment.section.size = prelude_size;
  hdr->header_segment.section.offset = 0;
#define S_ATTR_SOME_INSTRUCTIONS 0x400
  hdr->header_segment.section.flags = 0;
  hdr->header_segment.section.alignment_hint = 14;
  sprintf(hdr->segment.segname, "__TEXT");
  hdr->segment.cmd = LC_SEGMENT_64;
  hdr->segment.cmdsize = sizeof(hdr->segment);
  hdr->segment.maxprot = 7;
  hdr->segment.initprot = 7;
  hdr->segment.vmaddr = VIRT_BASE - prelude_size;
  hdr->segment.vmsize = image_size + prelude_size;
  hdr->segment.fileoff = 0;
  hdr->segment.filesize = image_size + prelude_size;
  hdr->segment.nsects = 1;
  sprintf(hdr->segment.section.sectname, "__text");
  sprintf(hdr->segment.section.segname, "__TEXT");
  hdr->segment.section.addr = VIRT_BASE - prelude_size;
  hdr->segment.section.size = image_size + prelude_size;
  hdr->segment.section.offset = 0;
#define S_ATTR_SOME_INSTRUCTIONS 0x400
  hdr->segment.section.flags = S_ATTR_SOME_INSTRUCTIONS;
  hdr->segment.section.alignment_hint = 22; /* not obeyed */
#define LC_UNIXTHREAD   0x5
  hdr->thread.cmd = LC_UNIXTHREAD;
  hdr->thread.cmdsize = sizeof(hdr->thread);
#define ARM_THREAD_STATE64 6
  hdr->thread.flavor = ARM_THREAD_STATE64;
  hdr->thread.count = 68;
  hdr->thread.pc = VIRT_BASE - prelude_size + HDR_SIZE;
  void *image = buf + prelude_size;
#define MOV_X0_0 0xd2800000
  assert(HDR_SIZE >= sizeof(*hdr));
  assert(HDR_SIZE%8 == 0);
#define SNIPPET(name) do {			\
    memcpy(p, name, sizeof(name));		\
    p = (void *)p + sizeof(name);		\
  } while (0)
  for (uint32_t *p = buf + HDR_SIZE; (void *)p < buf + prelude_size;)
    SNIPPET(nop);
  uint32_t *p = buf + HDR_SIZE;
  p = buf + HDR_SIZE;

  SNIPPET(save_boot_args);
  //SNIPPET(disable_timers);
  //SNIPPET(x8r8g8b8);
  SNIPPET(perform_alignment_4);
  SNIPPET(enable_all_clocks);
  //SNIPPET(bring_up_phys_2);
  SNIPPET(restore_boot_args);
  assert((void *)p <= buf + prelude_size);
  fread(image, image_size, 1, f);
  fclose(f);
  f = fopen(argv[2], "w");
  if (!f)
    goto error;
  fwrite(buf, 1, prelude_size + image_size, f);
  fclose(f);
  return 0;
}
