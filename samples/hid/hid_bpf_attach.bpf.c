// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hid_bpf_attach.h"
#include "hid_bpf_helpers.h"

SEC("syscall")
int attach_prog(struct attach_prog_args *ctx)
{
    bpf_printk("attach_prog: Executing attach_prog\n");
	ctx->retval = hid_bpf_attach_prog(ctx->hid,
					  ctx->prog_fd,
					  0);
    sid_bpf_testing();
	return 0;
}
