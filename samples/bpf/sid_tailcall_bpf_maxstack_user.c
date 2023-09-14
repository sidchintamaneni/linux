#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>


int main(int argc, char **argv){
    
    struct bpf_link *link = NULL;
    struct bpf_program *prog;
    struct bpf_object *obj;

    char filename[256];
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

    obj = bpf_object__open_file(filename, NULL);
    if(libbpf_get_error(obj)){
        fprintf(stderr, "Error: opening BPF obj file");
        return 0;
    }

    prog = bpf_object__find_program_by_name(obj, "bpf_max_stack_enter");
    if(!prog){
        fprintf(stderr,"finding the prog in the object file failed\n");
        goto cleanup;
    }

    if (bpf_object__load(obj)) {
                fprintf(stderr, "ERROR: loading BPF object file failed\n");
                goto cleanup;
    }

    link = bpf_program__attach(prog);
    if(libbpf_get_error(link)){
        fprintf(stderr, "ERROR: bpf_program__attach failed : %ld\n", libbpf_get_error(link));
        link = NULL;
        goto cleanup;
    }else{
        fprintf(stderr, "Attachment is done\n");
    }
//    read_trace_pipe();
    while(1);
    cleanup:
            bpf_link__destroy(link);
            bpf_object__close(obj);
            return 0;

}
