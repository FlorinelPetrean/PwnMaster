#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char check[8];
    char buf[16];
    printf("test angr\n");
    fgets(check, 16, stdin);

    if(strcmp(buf, "UTCN") == 0) {
        gets(buf);
        printf("Good");

    }
    else {
        printf("Bad");
    }





}