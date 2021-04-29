int main(int argc, char **argv)
{

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
  hdr->header.ncmds = 3;
  hdr->header.sizeofcmds = sizeof(hdr->header_segment) + sizeof(hdr->segment) + sizeof(hdr->thread);
#define MH_DYLDLINK     0x00000004
  hdr->header.flags = MH_DYLDLINK;

#define LC_SEGMENT_64   0x19
  sprintf(hdr->header_segment.segname, "__HEADER");
  hdr->header_segment.cmd = LC_SEGMENT_64;
  hdr->header_segment.cmdsize = sizeof(hdr->segment);
  hdr->header_segment.maxprot = 1;
  hdr->header_segment.initprot = 1;
  hdr->header_segment.vmaddr = 0xfffffe0006ffc000;
  hdr->header_segment.vmsize = 16384;
  hdr->header_segment.fileoff = 0;
  hdr->header_segment.filesize = 16384;
  hdr->header_segment.nsects = 1;
  sprintf(hdr->header_segment.section.sectname, "__header");
  sprintf(hdr->header_segment.section.segname, "__HEADER");
  hdr->header_segment.section.addr = 0xfffffe0006ffc000;
  hdr->header_segment.section.size = 16384;
  hdr->header_segment.section.offset = 0;
#define S_ATTR_SOME_INSTRUCTIONS 0x400
  hdr->header_segment.section.flags = 0;
  hdr->header_segment.section.align = 14;
  sprintf(hdr->segment.segname, "__TEXT");
  hdr->segment.cmd = LC_SEGMENT_64;
  hdr->segment.cmdsize = sizeof(hdr->segment);
  hdr->segment.maxprot = 7;
  hdr->segment.initprot = 7;
  hdr->segment.vmaddr = 0xfffffe0007000000;
  hdr->segment.vmsize = size;
  hdr->segment.fileoff = 16384 + 0;
  hdr->segment.filesize = size;
  hdr->segment.maxprot = 7;
  hdr->segment.nsects = 1;
  sprintf(hdr->segment.section.sectname, "__text");
  sprintf(hdr->segment.section.segname, "__TEXT");
  hdr->segment.section.addr = 0xfffffe0007000000;
  hdr->segment.section.size = size;
  hdr->segment.section.offset = 0;
#define S_ATTR_SOME_INSTRUCTIONS 0x400
  hdr->segment.section.flags = S_ATTR_SOME_INSTRUCTIONS;
  hdr->segment.section.align = 22;
#define LC_UNIXTHREAD   0x5
  hdr->thread.cmd = LC_UNIXTHREAD;
  hdr->thread.cmdsize = sizeof(hdr->thread);
#define ARM_THREAD_STATE64 6
  hdr->thread.flavor = ARM_THREAD_STATE64;
  hdr->thread.count = 68;
  hdr->thread.pc = 0xfffffe0007002000;
  void *image = buf + 16384;
  for (uint32_t *p = buf + 0x2000; p < buf + 0x4000; p++)
    *p = 0xd2800003;
  uint32_t *p = buf + 0x2000;
  //memmove(p, remap_to_physical, sizeof(remap_to_physical));
  //p = (void *)p + sizeof(remap_to_physical);

  //memcpy(buf + 0x4000 - sizeof(reboot_physical), reboot_physical,
  //sizeof(reboot_physical));
  //memcpy(buf + 0x4000 - sizeof(code_at_eoh), code_at_eoh,
  //sizeof(code_at_eoh));
  fread(image, size, 1, f);
  p = image + 0x2000;
  //memcpy(p, remap_to_physical, sizeof(remap_to_physical));
  //p = (void *)p + sizeof(remap_to_physical);
  memcpy(p, perform_alignment_2, sizeof(perform_alignment_2));
  p = (void *)p + sizeof(perform_alignment_2);
  memcpy(p, enable_all_clocks, sizeof(enable_all_clocks));
  p = (void *)p + sizeof(enable_all_clocks);
  memcpy(p, bring_up_phys, sizeof(bring_up_phys));
  p = (void *)p + sizeof(bring_up_phys);
  memcpy(p, x8r8g8b8, sizeof(x8r8g8b8));
  p = (void *)p + sizeof(x8r8g8b8);
  *p++ = 0xd2800000;
  memcpy(p, jump_to_start_of_page, sizeof(jump_to_start_of_page));
  p = (void *)p + sizeof(jump_to_start_of_page);
  fclose(f);
  f = fopen(argv[2], "w");
  if (!f)
    goto error;
  fwrite(buf, 1, 16384 + size, f);
  fclose(f);
  return 0;
}
