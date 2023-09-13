#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>


int main(int argc, char **argv)
{
    printf("Inside Userspace Main Function\n");
    int ret = -1;
    const char *pinned_file = "/sys/fs/bpf/prog_array_init";
    const char *pinned_file2 = "/sys/fs/bpf/tailcall_prog";

    int map_fd = bpf_obj_get(pinned_file);
    if(map_fd<0){
        fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
                pinned_file, strerror(errno), errno);
        goto out;
    }


    int tail_prog_fd = bpf_obj_get(pinned_file2);
    int key = 1;
    bpf_map_update_elem(map_fd, &key, &tail_prog_fd, 0);

out:
    if(map_fd!= -1)
        close(map_fd);
    return ret;

}
