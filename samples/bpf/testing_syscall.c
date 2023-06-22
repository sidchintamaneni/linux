#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

/*
 * Put your syscall number here.
 */
#define SYS_cust_net 335

int main(int argc, char **argv)
{

  long res = syscall(SYS_cust_net);
  printf("System call returned %ld.\n", res);
  return res;
}

