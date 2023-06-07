#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include <netinet/ip_icmp.h>

#include "trace_common.h"
int main(int argc, char **argv)
{
    printf("Inside Userspace Main Function\n");
    int ret = -1;
    const char *pinned_file = "/sys/fs/bpf/tc/globals/icmp_ingress_data";

    int map_fd = bpf_obj_get(pinned_file);
    if(map_fd<0){
        fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
                pinned_file, strerror(errno), errno);
        goto out;
    }
//    int key = 0;
//    while(1) {
        struct icmphdr *icmp;
        icmp = malloc(sizeof(struct icmphdr));
//      int val; 
        bpf_map_lookup_and_delete_elem(map_fd, NULL, icmp);

        printf("ICMP type: %d\n", icmp->type); 
        printf("ICMP code: %d\n", icmp->code);
//    }
//    printf("value: %d\n", val);
    ret = 0;


out:
    if(map_fd!= -1)
        close(map_fd);
    return ret;

}

