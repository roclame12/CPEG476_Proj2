#include <stdlib.h>
#include <stdio.h>

void win(){
    system("/bin/sh");

}

void vuln(){
    char buf[0x42];
    gets(buf);
}

int main(){
    puts("Oh baby a triple...\n");
    vuln();
    return 0;
}
