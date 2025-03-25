#include <stdio.h> 
#include <stdlib.h> 

int main(){
   int overwrite_me;
   int overwrite_me_too;

   char buf[0x70];
   puts("Welcome to pwn 101");
   overwrite_me = 0xb4be;
   overwrite_me_too = 0xf47b47;
   fgets(buf, 0x90, stdin);

   if (overwrite_me == 0xf47b47 && overwrite_me_too == 0xb4be){
       puts("Ooh you are ready for pwn 102\n");
       system("/bin/sh");
   }
   else{
       puts("Summer school 4 u?\n");
   }


}
