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
    __builtin_unreachable();
}
