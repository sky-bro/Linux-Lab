# getopt 命令行参数解析

## 介绍

* 用来解析命令行参数，`argv`是一个字符串数组，`argc`表示这个数组的长度，`argv[0]`是程序名，所以参数解析是从`argv[1]`开始。`-`开始的串表示选项（或者`--`开始，如果使用长选项），它后面的一个串表示选项的参数（也可能不是，因为选项可以没有参数）
* 当没有参数解析的时候，函数返回`-1`
* `man 3 getopt`
* 功能说明
  * `getopt`: 获取短参数，它可以获取`-a`，`-l`类型的短参数，也可以`-al`合并的获取到`a`和`l`
  * `getopt_long`: 在`getopt`的基础上获取长参数，它还可以获取`--help`这种参数
  * `getopt_long_only`: 也是在上一个函数基础上有所增加，输入长参数可以不用输入两个`--`，而是可以直接用`-help`

### SYNOPSIS

* `#include <unistd.h>`
  * `int getopt(int argc, char * const argv[],const char *optstring);`
  * `extern char *optarg;` 存储选项的参数
  * `extern int optind, opterr, optopt;`
    * `optind` 是argv的下标，`argv[optind]`表示下一个待解析的参数，`optind`初始值为1
    * `opterr` 是否显示错误信息，非零显示，0不显示，一般我们把它设为0
    * `optopt` 如果出现错误，保存出错的那个选项

* `#include <getopt.h>`
  * `int getopt_long(int argc, char * const argv[],const char *optstring,const struct option *longopts, int *longindex)`
  * `int getopt_long_only(int argc, char * const argv[],const char *optstring,const struct option *longopts, int *longindex)`

### 参数说明

* `argc`和`argv` 就是传递给main函数的两个参数，`argv`就是程序运行时的程序名以及它的参数，是一个字符串数组，`argc`就是这个字符串数组的长度
* `optstring` 指定需要解析的短参数，比如`"abc:d:e::"`表示有`abcde`这5种参数，而且`ab`不带参数，`c`带参数(后面跟的`:`表示后面必须跟一个参数)，`e`可带可不带参数(后面跟的`::`表示选项参数是可选的，如果带参数必须紧挨着选项，也就是`-exxx`，不能有空格隔开如`-e xxx`，隔开则视为没有带参数)，选项参数由`optarg`指向
* `longopts` 指向option数组，包含了长选项的信息，下一节详细介绍这个结构体
* `longindex` 如果不是null，那么将解析参数时将把它指向的变量设为对应的`longopts`数组的下标

### option结构体

```c
struct option {
    const char *name;    // --<name> name of the long option
    int         has_arg; // no_argument (or 0), required_argument (or 1), optional_argument (or 2)
    int        *flag;    // set *flag to val and returns 0 if not null
    int         val;     // value to return or to load into *flag
}
```

* `name` 表示长选项的名字，使用时就是用`--<name>`的形式
* `has_arg` 用来指示这个选项的参数要求，`no_argument`或者`0`表示不带参数，`required_argument`或者`1`表示必须带参数，`optional_argument`或者`2`表示参数是可选的
* `flag` 通常设为0，若不为0,那么解析参数时将会把`*flag`设置为val，然后函数返回0
* `val` 解析到参数时函数返回的值，或者设置`*flag`的值，通常把它设为对应的短参数字符

### 错误参数处理

两种错误，一个是出现不认识的选项，另一个是需要带参数的选项没有带参数

* 默认情况，遇到错误，输出错误信息，把出错的那个选项保存到`optopt`，然后返回`?`
* 如果`opterr`设为了0，则不输出错误信息，可以通过是否返回`?`来判定是否出错(默认情况`opterr`非0)
* 如果`optstring`的第一个字符(也可能是第二个，如果开头有`+-`的话)是`:`，那么也不会输出错误信息，然后会返回`:`表示缺少选项参数或者返回`?`表示出现不认识的选项(这样就能把两种错误区分开了)

## 使用getopt

### 示例代码`getopt-test.c`

```c
// getopt-test.c
// gcc -g -o getopt-test getopt-test.c
#include <getopt.h>
#include <stdio.h>

int main(int argc, char *const argv[]) {
  char c;
  while ((c = getopt(argc, argv, "abc:d::")) != -1) {
    //   while ((c = getopt(argc, argv, ":abc:d::")) != -1) {
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
```

### 运行情况

* `optstring`前面不带`:`时

```txt
> ./getopt-test -d -d123 -c 456 -afc
got d
no argument for d
got d
argument for d is: 123
got 'c'
argument for c is: 456
got a
./getopt-test: invalid option -- 'f'
got 63 (?), optopt: 102 (f)
./getopt-test: option requires an argument -- 'c'
got 63 (?), optopt: 99 (c)
```

当遇到解析参数错误时（也就是上面说的两种错误），会输出错误提示，而且返回的字符都是`?`

* `optstring`前面带`:`时，同样的命令

```txt
> ./getopt-test -d -d123 -c 456 -afc
got d
no argument for d
got d
argument for d is: 123
got 'c'
argument for c is: 456
got a
got 63 (?), optopt: 102 (f)
got 58 (:), optopt: 99 (c)
```

这样可以区分出是哪一种错误（如果你需要的话），而且不会输出错误信息

* 另外如果将`opterr`设为0的话也不会输出错误信息

## 使用getopt_long

### 示例代码getopt_long-test.c

```c

```

### 运行情况

## more

* shell中的getopt -- todo
