#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


void vuln() {
    char buf[40];
    char magic[10], magic2[10], magic3[10], magic5[10], magic6[10], magic7[10], magic8[10], magic9[10], magic10[10];
    int magic4;
    printf("Test binary\n");
    read(0, magic, 10);
    read(0, magic2, 10);
    read(0, magic5, 10);
    read(0, magic6, 10);
    read(0, magic7, 10);
    read(0, magic8, 10);
    read(0, magic9, 10);
    read(0, magic10, 10);
    scanf("%d", &magic4);

    if(magic4 == 42) {
        if(strncmp(magic, "magic1", 6) == 0) {
            if(strncmp(magic2, "magic2", 6) == 0){
                if(strncmp(magic5, "magic5", 6) == 0){
                    if(strncmp(magic6, "magic6", 6) == 0){
                        if(strncmp(magic7, "magic7", 6) == 0){
                            if(strncmp(magic8, "magic8", 6) == 0){
                                if(strncmp(magic9, "magic9", 6) == 0){
                                    if(strncmp(magic10, "magic10", 7) == 0){
                                        printf("Found vuln!\n");
                                        fgets(buf, 100, stdin);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (strncmp(buf, "UTCN", 4) != 0) {
        exit(1);
    }
    read(0, magic3, 10);
    if(strncmp(magic3, "magic3", 5) != 0) {
        exit(1);
    }
}

int main() {

    vuln();
    return 0;
}