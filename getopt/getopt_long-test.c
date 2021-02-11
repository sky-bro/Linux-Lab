// getopt_long-test.c
// gcc -g -o getopt_long-test getopt_long-test.c
// ./getopt_long-test -e s --name sky --delete 123 -d123 --delete=123 --new --add -fe
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *const argv[]) {
  char c;
  //   opterr = 0;
  int ret, longind;
  struct option long_options[] = {{"add", no_argument, 0, 'a'},
                                  {"new", no_argument, 0, 'n'},
                                  {"name", required_argument, 0, 256},
                                  {"create", required_argument, 0, 'c'},
                                  {"delete", optional_argument, 0, 'd'},
                                  {0, 0, 0, 0}};
  while ((ret = getopt_long(argc, argv, "anc:e:d::", long_options, &longind)) != -1) {
//   while ((ret = getopt_long(argc, argv, ":anc:e:d::", long_options, &longind)) != -1) {
    switch (ret) {
      case 'a':
        printf("got 'a', longind is: %d\n", longind);
        break;
      case 'n':
        printf("got 'n', longind is: %d\n", longind);
        break;
      case 256:
        printf("%s %s\n", long_options[longind].name, optarg);
        break;
      case 'c':
        printf("got 'c', longind is: %d\n", longind);
        break;
      case 'd':
        printf("got 'd', longind is: %d\n", longind);
        if (optarg) {
          printf("optional argument is: %s\n", optarg);
        } else {
          printf("no argument\n");
        }
        break;
      case 'e':
        printf("got 'e' -- %s\n", optarg);
        break;
      default:
        printf("got %d (%c), optopt: %d (%c)\n", c, c, optopt, optopt);
        break;
    }
  }
  return 0;
}
