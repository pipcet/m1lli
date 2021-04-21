#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

#define BUFSIZE 65536

static unsigned char buf[BUFSIZE];

int handle_byte(unsigned char byte)
{
  static size_t count;
  static size_t size;
  if (count < 8) {
    size += (byte << count);
    return 0;
  }
  if (size == 0)
    return -1;

  return 0;
}

int main(void)
{
  printf("Th1s is m1lli\n");
  mkdir("m1lli-data", 0755);
  chdir("m1lli-data");
  int ttyfd = open("/dev/ttyGS0", O_RDWR);
  if (ttyfd < 0)
    return 1;
  FILE *tarfile = popen("/bin/busybox tar xv", "w");
  if (tarfile == 0)
    return 1;
  int tarfd = fileno(tarfile);
  size_t size = (size_t)-1;
  ssize_t ret;
  size_t count = 0;
  struct timeval tv0, tv1;

  gettimeofday(&tv0, NULL);

  while (1) {
    struct pollfd pfd[2] = {
      { .fd = ttyfd, .events = POLLIN, .revents = 0 },
      { .fd = tarfd, .events = 0, .revents = 0 },
    };

    if (poll(pfd, 2, 1000) < 0)
      return 1;

    if (pfd[1].revents & POLLHUP)
      return 0;

    if (access(".done", F_OK) == 0)
      return 0;

    if (pfd[0].revents & POLLIN) {
      ret = read(ttyfd, buf, BUFSIZE);
      if (ret <= 0)
	return 1;
    } else {
      ret = 0;
    }

    if (size == (size_t)-1) {
      int cnt = sscanf(buf, "%lld\n", &size);
      if (cnt > 0) {
	write(tarfd, buf + cnt, ret - cnt);
	count += ret - cnt;
      }
    } else {
      write(tarfd, buf, ret);
      count += ret;
    }
    gettimeofday(&tv1, NULL);
    unsigned long long delta = (long long)(tv1.tv_sec - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
    printf("read %lld+%lld bytes in %lld us, %f bytes/s\n",
	   (long long) count, (long long) ret, delta, (double)count/delta*1e6);
    if (delta > 15000000)
      return 0;
    if (count >= size)
      return 0;
  }

  return 0;
}
