#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char buf[16];
    char magic[10];
    char magic2[10];
    char magic3[10];
    printf("Test binary\n");
    read(0, magic, 10);
    read(0, magic2, 10);
//    scanf("%d", &magic3);


    printf("Main Function is at: %lx\n", main);

    read(0, magic3, 10);

    printf(magic3);

//    if(magic3 == 69) {
        if(strcmp(magic, "magic1") == 0) {
            if(strcmp(magic2, "magic2") == 0){
                printf("Found vuln!\n");
                read(0, buf, 100);
//                gets(buf);
            }
        }
//    }

    if (strncmp(buf, "UTCN", 4) != 0) {
        exit(1);
    }



    printf("Go to return!\n");

    return 0;
}