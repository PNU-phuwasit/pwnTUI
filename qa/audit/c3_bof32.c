// 3. 32-bit classic buffer overflow
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) { system("/bin/sh -c 'echo PWNED32'"); }

void vuln(void) {
    char buf[40];
    puts("32bit> ");
    read(0, buf, 256);
    printf("got %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
