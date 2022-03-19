#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    puts("Hello vuln!");
    char buf[100];
    char magic1[10];
    fgets(magic1, 10, stdin);
    if (strncmp(magic1, "magic1", 6) == 0) {
//        fgets(buf, 200, stdin);

        gets(buf);
        printf(buf);
    }
//    char binsh[15];
//    gets(binsh);
//    printf(binsh);
    exit(1);
}

int main() {

    vuln();

    return 0;
}