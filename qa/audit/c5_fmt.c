// 5. Format string nightmare -- rich-markup / raw byte rendering torture
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char scratch[256] = "[bold red]INJECTED[/bold red] \x1b[31mESC\x1b[0m {braces} \\backslash";
int target = 0;

void win(void) { system("/bin/sh -c 'echo PWNFMT'"); }

int main(void) {
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 0; i < 3; i++) {
        printf("fmt[%d]> ", i);
        if (!fgets(buf, sizeof buf, stdin)) break;
        printf(buf);            // <-- the bug
        putchar('\n');
    }
    if (target == 0xdeadbeef) win();
    return 0;
}
