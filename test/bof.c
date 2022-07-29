#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    puts("Hello world!");
    char buf[20];
    char magic1[10];
    char magic2[20];
    fgets(magic1, 10, stdin);


    if (strncmp(magic1, "magic1", 6) == 0) {
        fgets(buf, 100, stdin);
    }

    fgets(magic2, 10, stdin);
    if (!strncmp(magic2, "magic2", 6) == 0) {
        exit(1);
    }
}
int main() {
    vuln();
    return 0;
}