#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  char *path;
  if (argc < 2 || strcmp(argv[1], "--bootargs")) {
    asprintf(&path, "/sys/firmware/devicetree/base/reserved-memory/adt@800000000/reg");
  } else {
    asprintf(&path, "/sys/firmware/devicetree/base/reserved-memory/bootargs@800000000/reg");
  }
  int fd = open(path, O_RDONLY);
  uint64_t reg[2];
  if (fd < 0 || read(fd, reg, 16) != 16)
    goto error;
  reg[0] = __builtin_bswap64(reg[0]);
  reg[1] = __builtin_bswap64(reg[1]);
  close(fd);
  fd = open("/dev/mem", O_RDONLY);
  if (fd < 0)
    goto error;
  void *buf = mmap(NULL, reg[1], PROT_READ, MAP_SHARED, fd, reg[0]);
  if (buf == MAP_FAILED)
    goto error;
  void *buf2 = malloc(reg[1]);
  if (buf2 == NULL)
    goto error;
  volatile unsigned *p = buf;
  volatile unsigned *p2 = buf2;
  volatile unsigned *p3 = buf2;
  for (unsigned long off = 0; off < reg[1]; off += 4) {
    *p2++ = *p++;
    if (p2 - p3 >= 0x4000)
      p3 += write(1, p3, p2 - p3);
  }
  return 0;

 error:
  fprintf(stderr, "usage: %s\n", argv[0]);
  return 1;
}
