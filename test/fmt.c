#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    char buf[100];
    gets(buf);
    printf(buf);
}

int main() {

    vuln();
    printf("Go to return!\n");

    return 0;
}