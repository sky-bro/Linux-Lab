// getopt-test.c
// gcc -g -o getopt-test getopt-test.c
// ./getopt-test -d -d123 -c 456 -afc
#include <getopt.h>
#include <stdio.h>

int main(int argc, char *const argv[]) {
  char c;
  //   opterr = 0;
  while ((c = getopt(argc, argv, "abc:d::")) != -1) {
    //   while ((c = getopt(argc, argv, "：abc:d::")) != -1) {
    switch (c) {
      case 'a':
      case 'b':
        printf("got %c\n", c);
        break;
      case 'c':
        puts("got 'c'");
        printf("argument for c is: %s\n", optarg);
        break;
      case 'd':
        puts("got d");
        if (optarg) {
          printf("argument for d is: %s\n", optarg);
        } else {
          puts("no argument for d");
        }
        break;
      default:
        printf("got %d (%c), optopt: %d (%c)\n", c, c, optopt, optopt);
        break;
    }
  }
  return 0;
}
