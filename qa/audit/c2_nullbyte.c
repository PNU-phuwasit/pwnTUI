// 2. Null-byte trap: strcpy-based ret2win. strcpy stops at \x00.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) { system("/bin/sh -c 'echo PWNED'"); }

void vuln(char *src) {
    char buf[48];
    strcpy(buf, src);
    printf("copied: %s\n", buf);
}

int main(void) {
    char line[512];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("input> ");
    if (!fgets(line, sizeof line, stdin)) return 1;
    line[strcspn(line, "\n")] = 0;
    vuln(line);
    return 0;
}
