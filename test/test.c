#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char buf[10];
    char magic[10];
    char magic2[10];
    char magic3[10];
    int magic4;
    printf("Test binary\n");
    read(0, magic, 10);
    read(0, magic2, 10);
    scanf("%d", &magic4);

    if(magic4 == 69) {
        if(strcmp(magic, "012345678") == 0) {
            if(strcmp(magic2, "012345678") == 0){
                printf("Found vuln!\n");
                read(0, buf, 100);
//                gets(buf);
            }
        }
    }

    if (strncmp(buf, "UTCN", 4) != 0) {
        exit(1);
    }

//    scanf("%s", magic3);
    read(0, magic3, 10);

    if(strcmp(magic3, "wtfwtf") != 0) {
        exit(1);
    }

    printf("Go to return!\n");

    return 0;
}