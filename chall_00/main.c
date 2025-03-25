#include <stdio.h> 
#include <stdlib.h> 


int main(){
    char buf[0x50]; 
    int overwrite_me; 
    overwrite_me = 0x99; 
    puts("Ask me any question:\n"); 
    gets(buf); 
    if (overwrite_me == 0x13370420){ 
        system("/bin/sh"); 
    } 
    else{ 
        system("Nope; ls"); 
    } 
    return 0; 
} 
