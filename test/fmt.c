#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    char buf[200];
    char magic1[10];
    fgets(magic1, 10, stdin);
    if (strncmp(magic1, "magic1", 6) == 0) {
            fgets(buf, 200, stdin);
            printf(buf);
    }

    puts("Hello!");
}
int main() {
    vuln();
    return 0;
}