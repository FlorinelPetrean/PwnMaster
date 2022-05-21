#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    puts("Hello vuln!");
    char buf[10];
    char fmt[100] = "test";
    char magic1[10];
    char magic2[10];
    fgets(magic1, 10, stdin);
    fgets(magic2, 10, stdin);

    char magic3[10];
    fgets(magic3, 10, stdin);

    if (strncmp(magic2, "magic2", 6) == 0) {
        if (strncmp(magic1, "magic1", 6) == 0) {
    //        fgets(buf, 200, stdin);

            gets(buf);
            printf(buf);
        }
    }

//    if (strncmp(magic3, "A", 1) == 0)
        printf(magic3);

    char magic4[10];
    fgets(magic4, 10, stdin);
//    if (strncmp(magic4, "B", 1) == 0)
        printf(magic4);

//    exit(1);
    strcat(fmt, buf);
}

int main() {

    vuln();

    return 0;
}