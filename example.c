#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
  const int SIZE = 50;
  char data[SIZE] = {0};
  int size = read(STDIN_FILENO, data, SIZE);
  int *p = malloc(10);
  if (size >= 3) {
    if (data[0] == 'F' &&
             data[1] == 'U' &&
             data[2] == 'Z' &&
             data[3] == 'Z')
      free(p);
  }
  free(p);

  return 0;
}
