#include <unistd.h>
#include <fcntl.h>

#include "benchmark.h"

const char *filename = "test.txt";

int work() {
  int fd = open(filename, O_RDONLY, 0600);
  close(fd);
  return 0;
}

int main() {
  printf("Canary benchmark\n");
  return run_benchmark(work);
}