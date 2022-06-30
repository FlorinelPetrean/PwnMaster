#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    char buf[50];
    char magic1[10];
    char magic2[64];
    char magic3[20];
    fgets(magic1, 10, stdin);

    fgets(magic2, sizeof(magic2), stdin);
    printf(magic2);

    if (strncmp(magic1, "magic1", 6) == 0) {
        fgets(buf, 200, stdin);
    }

    fgets(magic3, 10, stdin);
    if (!strncmp(magic3, "magic3", 6) == 0) {
        exit(1);
    }
}
int main() {
    vuln();
    return 0;
}