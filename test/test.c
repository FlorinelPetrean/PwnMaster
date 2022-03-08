#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    char buf[100];
    char magic[10];
    char magic2[10];
    char magic3[10];
    int magic4;
    printf("Test binary\n");
    read(0, magic, 10);
    read(0, magic2, 10);
    scanf("%d", &magic4);

    if(magic4 == 69) {
        if(strncmp(magic, "012345678", 6) == 0) {
            if(strncmp(magic2, "012345678", 6) == 0){
                printf("Found vuln!\n");
//                read(0, buf, 80);
//                  fgets(buf, 120, stdin);
                gets(buf);
            }
        }
    }

//    if (strncmp(buf, "UTCN", 4) != 0) {
//        exit(1);
//    }

//    read(0, magic3, 10);
//
//    if(strncmp(magic3, "wtfwtf", 5) != 0) {
//        exit(1);
//    }

}

int main() {

    vuln();
    printf("Go to return!\n");

    return 0;
}