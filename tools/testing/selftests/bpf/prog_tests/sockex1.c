// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "sockex1.skel.h"
#include "sock_example.h"
#include <assert.h>

#define PING_CMD "ping -c1 127.0.0.1 > /dev/null"

void test_sockex1(void)
{
	struct sockex1 *sockex1_skel = NULL;
	struct bpf_program *prog;
	int err, sock_fd, prog_fd;

	sockex1_skel = sockex1__open();
	if (!ASSERT_OK_PTR(sockex1_skel, "sockex1_skel_open"))
		goto close_prog;

	prog = sockex1_skel->progs.bpf_prog1;
	bpf_program__set_type(prog, BPF_PROG_TYPE_SOCKET_FILTER);

	err = sockex1__load(sockex1_skel);
	if (!ASSERT_OK_PTR(sockex1_skel, "sockex1_skel_load"))
		goto close_prog;

	err = sockex1__attach(sockex1_skel);
	if (!ASSERT_OK(err, "sockex1_attach"))
		goto close_prog;

	sock_fd = open_raw_sock("lo");
	prog_fd = bpf_program__fd(prog);
	//TODO: Don't use assert. Try some selftests semantics
	assert(setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) == 0);

	//TODO: ASSERT_OK instead of if
	if (!system(PING_CMD))
		goto close_prog;

	ASSERT_EQ(sockex1_skel->bss->invocation_icmp, 4, "sockex1 result");

close_prog:
	sockex1__destroy(sockex1_skel);
}
