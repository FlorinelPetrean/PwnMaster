#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void bla(int i) {
    system("/bin/sh\n");

}

void vuln() {
//    printf("Hello vuln!");
    char buf[100];
    char magic1[10];
    char magic2[20];
    char magic3[20];
    fgets(magic1, 10, stdin);

    fgets(magic2, 20, stdin);
    printf(magic2);

    printf("Vuln Function is at: %lx\n", vuln);
    if (strncmp(magic1, "magic1", 6) == 0) {
        gets(buf);
    }

//    exit(1);
}

int main() {

    vuln();

    return 0;
}