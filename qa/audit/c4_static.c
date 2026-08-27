// 4. Statically linked monster: no PLT/GOT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) { system("/bin/sh -c 'echo PWNSTATIC'"); }

void vuln(void) {
    char buf[64];
    read(0, buf, 512);
    char dst[32];
    strcpy(dst, buf);
    printf("static: %s\n", dst);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("static> ");
    vuln();
    return 0;
}
