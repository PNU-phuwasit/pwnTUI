// 1. Classic 64-bit ret2win, No-PIE, stripped, uses gets()
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    puts("[+] you win");
    system("/bin/sh -c 'echo PWNED'");
}

void vuln(void) {
    char buf[64];
    puts("Name: ");
    read(0, buf, 256);
    printf("hi %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
