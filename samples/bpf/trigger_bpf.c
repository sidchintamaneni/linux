#include <unistd.h>
#include <stdio.h>
#include <linux/unistd.h>

int main(void){
    printf("triggering syscall\n");
    return syscall(321);
}
