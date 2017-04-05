#include <stdio.h>

int main () {
  const int number = 100;
  int t1 = 0, t2 = 1;
  printf ("Fibonacci: %d, %d, ", t1, t2);
  int i;
  for (i = 3; i <= number; ++i) {
    int t3 = t1 + t2;
    t1 = t2;
    t2 = t3;
    printf("%d, ", t2);
  }
  printf("\n");
  return 0;
}

