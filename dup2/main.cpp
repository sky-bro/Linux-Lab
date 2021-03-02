#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

using namespace std;

int main(int argc, char const *argv[])
{
    int fd = open("out", O_WRONLY);
    if (fd < 0) {
        perror("open error");
        return 1;
    }
    dup2(fd, 1);
    cout << "hello from sky" << endl;
    return 0;
}
