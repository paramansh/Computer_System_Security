#include <stdio.h>
#include <fcntl.h>

int main() {
    int fd = open("temp.c", 'r');

    char buf[100]; 
    for(int i = 0; i < 100; i++) buf[i] = '0';
    buf[99] = '\0';
    int r = read(fd, &buf[102], 1);
    
    printf("%s %c %d", buf, buf[102], r);
    return 0;
}
