#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    char buf[100];
    char magic1[10];
    read(0, magic1, 10);
    if (strncmp(magic1, "magic1", 6) == 0) {
        gets(buf);
        printf(buf);
    }
}

int main() {

    vuln();
    printf("Go to return!\n");

    return 0;
}