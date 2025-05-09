// SPDX-License-Identifier: GPL-2.0

/* Reference program for verifying XDP metadata on real HW. Functional test
 * only, doesn't test the performance.
 *
 * RX:
 * - UDP 9091 packets are diverted into AF_XDP
 * - Metadata verified:
 *   - rx_timestamp
 *   - rx_hash
 *
 * TX:
 * - UDP 9091 packets trigger TX reply
 * - TX HW timestamp is requested and reported back upon completion
 * - TX checksum is requested
 * - TX launch time HW offload is requested for transmission
 */

#include <test_progs.h>
#include <network_helpers.h>
#include "xdp_hw_metadata.skel.h"
#include "xsk.h"

#include <error.h>
#include <linux/kernel.h>
#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/errqueue.h>
#include <linux/if_link.h>
#include <linux/net_tstamp.h>
#include <netinet/udp.h>
#include <linux/sockios.h>
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <net/if.h>
#include <ctype.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/ethtool.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "xdp_metadata.h"

#define UMEM_NUM 256
#define UMEM_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (UMEM_FRAME_SIZE * UMEM_NUM)
#define XDP_FLAGS (XDP_FLAGS_DRV_MODE | XDP_FLAGS_REPLACE)

struct xsk {
	void *umem_area;
	struct xsk_umem *umem;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons rx;
	struct xsk_socket *socket;
};

struct xdp_hw_metadata *bpf_obj;
__u16 bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY;
struct xsk *rx_xsk;
const char *ifname;
int ifindex;
int rxq;
bool skip_tx;
__u64 last_hw_rx_timestamp;
__u64 last_xdp_rx_timestamp;
__u64 last_launch_time;
__u64 launch_time_delta_to_hw_rx_timestamp;
int launch_time_queue;

#define run_command(cmd, ...)					\
({								\
	char command[1024];					\
	memset(command, 0, sizeof(command));			\
	snprintf(command, sizeof(command), cmd, ##__VA_ARGS__);	\
	fprintf(stderr, "Running: %s\n", command);		\
	system(command);					\
})

void test__fail(void) { /* for network_helpers.c */ }

static int open_xsk(int ifindex, struct xsk *xsk, __u32 queue_id)
{
	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	const struct xsk_socket_config socket_config = {
		.rx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.bind_flags = bind_flags,
	};
	const struct xsk_umem_config umem_config = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
		.flags = XDP_UMEM_TX_METADATA_LEN,
		.tx_metadata_len = sizeof(struct xsk_tx_metadata),
	};
	__u32 idx = 0;
	u64 addr;
	int ret;
	int i;

	xsk->umem_area = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
	if (xsk->umem_area == MAP_FAILED)
		return -ENOMEM;

	ret = xsk_umem__create(&xsk->umem,
			       xsk->umem_area, UMEM_SIZE,
			       &xsk->fill,
			       &xsk->comp,
			       &umem_config);
	if (ret)
		return ret;

	ret = xsk_socket__create(&xsk->socket, ifindex, queue_id,
				 xsk->umem,
				 &xsk->rx,
				 &xsk->tx,
				 &socket_config);
	if (ret)
		return ret;

	/* First half of umem is for TX. This way address matches 1-to-1
	 * to the completion queue index.
	 */

	for (i = 0; i < UMEM_NUM / 2; i++) {
		addr = i * UMEM_FRAME_SIZE;
		printf("%p: tx_desc[%d] -> %lx\n", xsk, i, addr);
	}

	/* Second half of umem is for RX. */

	ret = xsk_ring_prod__reserve(&xsk->fill, UMEM_NUM / 2, &idx);
	for (i = 0; i < UMEM_NUM / 2; i++) {
		addr = (UMEM_NUM / 2 + i) * UMEM_FRAME_SIZE;
		printf("%p: rx_desc[%d] -> %lx\n", xsk, i, addr);
		*xsk_ring_prod__fill_addr(&xsk->fill, idx + i) = addr;
	}
	xsk_ring_prod__submit(&xsk->fill, ret);

	return 0;
}

static void close_xsk(struct xsk *xsk)
{
	if (xsk->umem)
		xsk_umem__delete(xsk->umem);
	if (xsk->socket)
		xsk_socket__delete(xsk->socket);
	munmap(xsk->umem_area, UMEM_SIZE);
}

static void refill_rx(struct xsk *xsk, __u64 addr)
{
	__u32 idx;

	if (xsk_ring_prod__reserve(&xsk->fill, 1, &idx) == 1) {
		printf("%p: complete rx idx=%u addr=%llx\n", xsk, idx, addr);
		*xsk_ring_prod__fill_addr(&xsk->fill, idx) = addr;
		xsk_ring_prod__submit(&xsk->fill, 1);
	}
}

static int kick_tx(struct xsk *xsk)
{
	return sendto(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static int kick_rx(struct xsk *xsk)
{
	return recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(clockid_t clock_id)
{
	struct timespec t;
	int res;

	/* See man clock_gettime(2) for type of clock_id's */
	res = clock_gettime(clock_id, &t);

	if (res < 0)
		error(res, errno, "Error with clock_gettime()");

	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static void print_tstamp_delta(const char *name, const char *refname,
			       __u64 tstamp, __u64 reference)
{
	__s64 delta = (__s64)reference - (__s64)tstamp;

	printf("%s:   %llu (sec:%0.4f) delta to %s sec:%0.4f (%0.3f usec)\n",
	       name, tstamp, (double)tstamp / NANOSEC_PER_SEC, refname,
	       (double)delta / NANOSEC_PER_SEC,
	       (double)delta / 1000);
}

#define VLAN_PRIO_MASK		GENMASK(15, 13) /* Priority Code Point */
#define VLAN_DEI_MASK		GENMASK(12, 12) /* Drop Eligible Indicator */
#define VLAN_VID_MASK		GENMASK(11, 0)	/* VLAN Identifier */
static void print_vlan_tci(__u16 tag)
{
	__u16 vlan_id = FIELD_GET(VLAN_VID_MASK, tag);
	__u8 pcp = FIELD_GET(VLAN_PRIO_MASK, tag);
	bool dei = FIELD_GET(VLAN_DEI_MASK, tag);

	printf("PCP=%u, DEI=%d, VID=0x%X\n", pcp, dei, vlan_id);
}

static void verify_xdp_metadata(void *data, clockid_t clock_id)
{
	struct xdp_meta *meta;

	meta = data - sizeof(*meta);

	if (meta->hint_valid & XDP_META_FIELD_RSS)
		printf("rx_hash: 0x%X with RSS type:0x%X\n",
		       meta->rx_hash, meta->rx_hash_type);
	else
		printf("No rx_hash, err=%d\n", meta->rx_hash_err);

	if (meta->hint_valid & XDP_META_FIELD_TS) {
		__u64 ref_tstamp = gettime(clock_id);

		/* store received timestamps to calculate a delta at tx */
		last_hw_rx_timestamp = meta->rx_timestamp;
		last_xdp_rx_timestamp = meta->xdp_timestamp;

		print_tstamp_delta("HW RX-time", "User RX-time",
				   meta->rx_timestamp, ref_tstamp);
		print_tstamp_delta("XDP RX-time", "User RX-time",
				   meta->xdp_timestamp, ref_tstamp);
	} else {
		printf("No rx_timestamp, err=%d\n", meta->rx_timestamp_err);
	}

	if (meta->hint_valid & XDP_META_FIELD_VLAN_TAG) {
		printf("rx_vlan_proto: 0x%X\n", ntohs(meta->rx_vlan_proto));
		printf("rx_vlan_tci: ");
		print_vlan_tci(meta->rx_vlan_tci);
	} else {
		printf("No rx_vlan_tci or rx_vlan_proto, err=%d\n",
		       meta->rx_vlan_tag_err);
	}
}

static void verify_skb_metadata(int fd)
{
	char cmsg_buf[1024];
	char packet_buf[128];

	struct scm_timestamping *ts;
	struct iovec packet_iov;
	struct cmsghdr *cmsg;
	struct msghdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = &packet_iov;
	hdr.msg_iovlen = 1;
	packet_iov.iov_base = packet_buf;
	packet_iov.iov_len = sizeof(packet_buf);

	hdr.msg_control = cmsg_buf;
	hdr.msg_controllen = sizeof(cmsg_buf);

	if (recvmsg(fd, &hdr, 0) < 0)
		error(1, errno, "recvmsg");

	for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&hdr, cmsg)) {

		if (cmsg->cmsg_level != SOL_SOCKET)
			continue;

		switch (cmsg->cmsg_type) {
		case SCM_TIMESTAMPING:
			ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
			if (ts->ts[2].tv_sec || ts->ts[2].tv_nsec) {
				printf("found skb hwtstamp = %lu.%lu\n",
				       ts->ts[2].tv_sec, ts->ts[2].tv_nsec);
				return;
			}
			break;
		default:
			break;
		}
	}

	printf("skb hwtstamp is not found!\n");
}

static bool complete_tx(struct xsk *xsk, clockid_t clock_id)
{
	struct xsk_tx_metadata *meta;
	__u64 addr;
	void *data;
	__u32 idx;

	if (!xsk_ring_cons__peek(&xsk->comp, 1, &idx))
		return false;

	addr = *xsk_ring_cons__comp_addr(&xsk->comp, idx);
	data = xsk_umem__get_data(xsk->umem_area, addr);
	meta = data - sizeof(struct xsk_tx_metadata);

	printf("%p: complete tx idx=%u addr=%llx\n", xsk, idx, addr);

	if (meta->completion.tx_timestamp) {
		__u64 ref_tstamp = gettime(clock_id);

		if (launch_time_delta_to_hw_rx_timestamp) {
			print_tstamp_delta("HW Launch-time",
					   "HW TX-complete-time",
					   last_launch_time,
					   meta->completion.tx_timestamp);
		}
		print_tstamp_delta("HW TX-complete-time", "User TX-complete-time",
				   meta->completion.tx_timestamp, ref_tstamp);
		print_tstamp_delta("XDP RX-time", "User TX-complete-time",
				   last_xdp_rx_timestamp, ref_tstamp);
		print_tstamp_delta("HW RX-time", "HW TX-complete-time",
				   last_hw_rx_timestamp, meta->completion.tx_timestamp);
	} else {
		printf("No tx_timestamp\n");
	}

	xsk_ring_cons__release(&xsk->comp, 1);

	return true;
}

#define swap(a, b, len) do { \
	for (int i = 0; i < len; i++) { \
		__u8 tmp = ((__u8 *)a)[i]; \
		((__u8 *)a)[i] = ((__u8 *)b)[i]; \
		((__u8 *)b)[i] = tmp; \
	} \
} while (0)

static void ping_pong(struct xsk *xsk, void *rx_packet, clockid_t clock_id)
{
	struct xsk_tx_metadata *meta;
	struct ipv6hdr *ip6h = NULL;
	struct iphdr *iph = NULL;
	struct xdp_desc *tx_desc;
	struct udphdr *udph;
	struct ethhdr *eth;
	__sum16 want_csum;
	void *data;
	__u32 idx;
	int ret;
	int len;

	ret = xsk_ring_prod__reserve(&xsk->tx, 1, &idx);
	if (ret != 1) {
		printf("%p: failed to reserve tx slot\n", xsk);
		return;
	}

	tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);
	tx_desc->addr = idx % (UMEM_NUM / 2) * UMEM_FRAME_SIZE + sizeof(struct xsk_tx_metadata);
	data = xsk_umem__get_data(xsk->umem_area, tx_desc->addr);

	meta = data - sizeof(struct xsk_tx_metadata);
	memset(meta, 0, sizeof(*meta));
	meta->flags = XDP_TXMD_FLAGS_TIMESTAMP;

	eth = rx_packet;

	if (eth->h_proto == htons(ETH_P_IP)) {
		iph = (void *)(eth + 1);
		udph = (void *)(iph + 1);
	} else if (eth->h_proto == htons(ETH_P_IPV6)) {
		ip6h = (void *)(eth + 1);
		udph = (void *)(ip6h + 1);
	} else {
		printf("%p: failed to detect IP version for ping pong %04x\n", xsk, eth->h_proto);
		xsk_ring_prod__cancel(&xsk->tx, 1);
		return;
	}

	len = ETH_HLEN;
	if (ip6h)
		len += sizeof(*ip6h) + ntohs(ip6h->payload_len);
	if (iph)
		len += ntohs(iph->tot_len);

	swap(eth->h_dest, eth->h_source, ETH_ALEN);
	if (iph)
		swap(&iph->saddr, &iph->daddr, 4);
	else
		swap(&ip6h->saddr, &ip6h->daddr, 16);
	swap(&udph->source, &udph->dest, 2);

	want_csum = udph->check;
	if (ip6h)
		udph->check = ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					       ntohs(udph->len), IPPROTO_UDP, 0);
	else
		udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
						 ntohs(udph->len), IPPROTO_UDP, 0);

	meta->flags |= XDP_TXMD_FLAGS_CHECKSUM;
	if (iph)
		meta->request.csum_start = sizeof(*eth) + sizeof(*iph);
	else
		meta->request.csum_start = sizeof(*eth) + sizeof(*ip6h);
	meta->request.csum_offset = offsetof(struct udphdr, check);

	printf("%p: ping-pong with csum=%04x (want %04x) csum_start=%d csum_offset=%d\n",
	       xsk, ntohs(udph->check), ntohs(want_csum),
	       meta->request.csum_start, meta->request.csum_offset);

	/* Set the value of launch time */
	if (launch_time_delta_to_hw_rx_timestamp) {
		meta->flags |= XDP_TXMD_FLAGS_LAUNCH_TIME;
		meta->request.launch_time = last_hw_rx_timestamp +
					    launch_time_delta_to_hw_rx_timestamp;
		last_launch_time = meta->request.launch_time;
		print_tstamp_delta("HW RX-time", "HW Launch-time",
				   last_hw_rx_timestamp,
				   meta->request.launch_time);
	}

	memcpy(data, rx_packet, len); /* don't share umem chunk for simplicity */
	tx_desc->options |= XDP_TX_METADATA;
	tx_desc->len = len;

	xsk_ring_prod__submit(&xsk->tx, 1);
}

static int verify_metadata(struct xsk *rx_xsk, int rxq, int server_fd, clockid_t clock_id)
{
	const struct xdp_desc *rx_desc;
	struct pollfd fds[rxq + 1];
	__u64 comp_addr;
	__u64 deadline;
	__u64 addr;
	__u32 idx = 0;
	int ret;
	int i;

	for (i = 0; i < rxq; i++) {
		fds[i].fd = xsk_socket__fd(rx_xsk[i].socket);
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	fds[rxq].fd = server_fd;
	fds[rxq].events = POLLIN;
	fds[rxq].revents = 0;

	while (true) {
		errno = 0;

		for (i = 0; i < rxq; i++) {
			ret = kick_rx(&rx_xsk[i]);
			if (ret)
				printf("kick_rx ret=%d\n", ret);
		}

		ret = poll(fds, rxq + 1, 1000);
		printf("poll: %d (%d) skip=%llu fail=%llu redir=%llu\n",
		       ret, errno, bpf_obj->bss->pkts_skip,
		       bpf_obj->bss->pkts_fail, bpf_obj->bss->pkts_redir);
		if (ret < 0)
			break;
		if (ret == 0)
			continue;

		if (fds[rxq].revents)
			verify_skb_metadata(server_fd);

		for (i = 0; i < rxq; i++) {
			bool first_seg = true;
			bool is_eop = true;

			if (fds[i].revents == 0)
				continue;

			struct xsk *xsk = &rx_xsk[i];
peek:
			ret = xsk_ring_cons__peek(&xsk->rx, 1, &idx);
			printf("xsk_ring_cons__peek: %d\n", ret);
			if (ret != 1)
				continue;

			rx_desc = xsk_ring_cons__rx_desc(&xsk->rx, idx);
			comp_addr = xsk_umem__extract_addr(rx_desc->addr);
			addr = xsk_umem__add_offset_to_addr(rx_desc->addr);
			is_eop = !(rx_desc->options & XDP_PKT_CONTD);
			printf("%p: rx_desc[%u]->addr=%llx addr=%llx comp_addr=%llx%s\n",
			       xsk, idx, rx_desc->addr, addr, comp_addr, is_eop ? " EoP" : "");
			if (first_seg) {
				verify_xdp_metadata(xsk_umem__get_data(xsk->umem_area, addr),
						    clock_id);
				first_seg = false;

				if (!skip_tx) {
					/* mirror first chunk back */
					ping_pong(xsk, xsk_umem__get_data(xsk->umem_area, addr),
						  clock_id);

					ret = kick_tx(xsk);
					if (ret)
						printf("kick_tx ret=%d\n", ret);

					/* wait 1 second + cover launch time */
					deadline = gettime(clock_id) +
						   NANOSEC_PER_SEC +
						   launch_time_delta_to_hw_rx_timestamp;
					while (true) {
						if (complete_tx(xsk, clock_id))
							break;
						if (gettime(clock_id) >= deadline)
							break;
						usleep(10);
					}
				}
			}

			xsk_ring_cons__release(&xsk->rx, 1);
			refill_rx(xsk, comp_addr);
			if (!is_eop)
				goto peek;
		}
	}

	return 0;
}

static int rxq_num(const char *ifname)
{
	struct ethtool_channels ch = {
		.cmd = ETHTOOL_GCHANNELS,
	};

	struct ifreq ifr = {
		.ifr_data = (void *)&ch,
	};
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		error(1, errno, "socket");

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret < 0)
		error(1, errno, "ioctl(SIOCETHTOOL)");

	close(fd);

	return ch.rx_count + ch.combined_count;
}

static void hwtstamp_ioctl(int op, const char *ifname, struct hwtstamp_config *cfg)
{
	struct ifreq ifr = {
		.ifr_data = (void *)cfg,
	};
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		error(1, errno, "socket");

	ret = ioctl(fd, op, &ifr);
	if (ret < 0)
		error(1, errno, "ioctl(%d)", op);

	close(fd);
}

static struct hwtstamp_config saved_hwtstamp_cfg;
static const char *saved_hwtstamp_ifname;

static void hwtstamp_restore(void)
{
	hwtstamp_ioctl(SIOCSHWTSTAMP, saved_hwtstamp_ifname, &saved_hwtstamp_cfg);
}

static void hwtstamp_enable(const char *ifname)
{
	struct hwtstamp_config cfg = {
		.rx_filter = HWTSTAMP_FILTER_ALL,
		.tx_type = HWTSTAMP_TX_ON,
	};

	hwtstamp_ioctl(SIOCGHWTSTAMP, ifname, &saved_hwtstamp_cfg);
	saved_hwtstamp_ifname = strdup(ifname);
	atexit(hwtstamp_restore);

	hwtstamp_ioctl(SIOCSHWTSTAMP, ifname, &cfg);
}

static void cleanup(void)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	int ret;
	int i;

	if (bpf_obj) {
		opts.old_prog_fd = bpf_program__fd(bpf_obj->progs.rx);
		if (opts.old_prog_fd >= 0) {
			printf("detaching bpf program....\n");
			ret = bpf_xdp_detach(ifindex, XDP_FLAGS, &opts);
			if (ret)
				printf("failed to detach XDP program: %d\n", ret);
		}
	}

	for (i = 0; i < rxq; i++)
		close_xsk(&rx_xsk[i]);

	if (bpf_obj)
		xdp_hw_metadata__destroy(bpf_obj);

	free((void *)saved_hwtstamp_ifname);
}

static void handle_signal(int sig)
{
	/* interrupting poll() is all we need */
}

static void timestamping_enable(int fd, int val)
{
	int ret;

	ret = setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &val, sizeof(val));
	if (ret < 0)
		error(1, errno, "setsockopt(SO_TIMESTAMPING)");
}

static void print_usage(void)
{
	const char *usage =
		"Usage: xdp_hw_metadata [OPTIONS] [IFNAME]\n"
		"  -c    Run in copy mode (zerocopy is default)\n"
		"  -h    Display this help and exit\n\n"
		"  -m    Enable multi-buffer XDP for larger MTU\n"
		"  -r    Don't generate AF_XDP reply (rx metadata only)\n"
		"  -l    Delta of launch time relative to HW RX-time in ns\n"
		"        default: 0 ns (launch time request is disabled)\n"
		"  -L    Tx Queue to be enabled with launch time offload\n"
		"        default: 0 (Tx Queue 0)\n"
		"Generate test packets on the other machine with:\n"
		"  echo -n xdp | nc -u -q1 <dst_ip> 9091\n";

	printf("%s", usage);
}

static void read_args(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "chmrl:L:")) != -1) {
		switch (opt) {
		case 'c':
			bind_flags &= ~XDP_USE_NEED_WAKEUP;
			bind_flags &= ~XDP_ZEROCOPY;
			bind_flags |= XDP_COPY;
			break;
		case 'h':
			print_usage();
			exit(0);
		case 'm':
			bind_flags |= XDP_USE_SG;
			break;
		case 'r':
			skip_tx = true;
			break;
		case 'l':
			launch_time_delta_to_hw_rx_timestamp = atoll(optarg);
			break;
		case 'L':
			launch_time_queue = atoll(optarg);
			break;
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option: -%c\n", optopt);
			fallthrough;
		default:
			print_usage();
			error(-1, opterr, "Command line options error");
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "No device name provided\n");
		print_usage();
		exit(-1);
	}

	ifname = argv[optind];
	ifindex = if_nametoindex(ifname);

	if (!ifname)
		error(-1, errno, "Invalid interface name");
}

void clean_existing_configurations(void)
{
	/* Check and delete root qdisc if exists */
	if (run_command("sudo tc qdisc show dev %s | grep -q 'qdisc mqprio 8001:'", ifname) == 0)
		run_command("sudo tc qdisc del dev %s root", ifname);

	/* Check and delete ingress qdisc if exists */
	if (run_command("sudo tc qdisc show dev %s | grep -q 'qdisc ingress ffff:'", ifname) == 0)
		run_command("sudo tc qdisc del dev %s ingress", ifname);

	/* Check and delete ethtool filters if any exist */
	if (run_command("sudo ethtool -n %s | grep -q 'Filter:'", ifname) == 0) {
		run_command("sudo ethtool -n %s | grep 'Filter:' | awk '{print $2}' | xargs -n1 sudo ethtool -N %s delete >&2",
			    ifname, ifname);
	}
}

#define MAX_TC 16

int main(int argc, char *argv[])
{
	clockid_t clock_id = CLOCK_TAI;
	struct bpf_program *prog;
	int server_fd = -1;
	size_t map_len = 0;
	size_t que_len = 0;
	char *buf = NULL;
	char *map = NULL;
	char *que = NULL;
	char *tmp = NULL;
	int tc = 0;
	int ret;
	int i;

	read_args(argc, argv);

	rxq = rxq_num(ifname);
	printf("rxq: %d\n", rxq);

	if (launch_time_queue >= rxq || launch_time_queue < 0)
		error(1, 0, "Invalid launch_time_queue.");

	clean_existing_configurations();
	sleep(1);

	/* Enable tx and rx hardware timestamping */
	hwtstamp_enable(ifname);

	/* Prepare priority to traffic class map for tc-mqprio */
	for (i = 0; i < MAX_TC; i++) {
		if (i < rxq)
			tc = i;

		if (asprintf(&buf, "%d ", tc) == -1) {
			printf("Failed to malloc buf for tc map.\n");
			goto free_mem;
		}

		map_len += strlen(buf);
		tmp = realloc(map, map_len + 1);
		if (!tmp) {
			printf("Failed to realloc tc map.\n");
			goto free_mem;
		}
		map = tmp;
		strcat(map, buf);
		free(buf);
		buf = NULL;
	}

	/* Prepare traffic class to hardware queue map for tc-mqprio */
	for (i = 0; i <= tc; i++) {
		if (asprintf(&buf, "1@%d ", i) == -1) {
			printf("Failed to malloc buf for tc queues.\n");
			goto free_mem;
		}

		que_len += strlen(buf);
		tmp = realloc(que, que_len + 1);
		if (!tmp) {
			printf("Failed to realloc tc queues.\n");
			goto free_mem;
		}
		que = tmp;
		strcat(que, buf);
		free(buf);
		buf = NULL;
	}

	/* Add mqprio qdisc */
	run_command("sudo tc qdisc add dev %s handle 8001: parent root mqprio num_tc %d map %squeues %shw 0",
		    ifname, tc + 1, map, que);

	/* To test launch time, send UDP packet with VLAN priority 1 to port 9091 */
	if (launch_time_delta_to_hw_rx_timestamp) {
		/* Enable launch time hardware offload on launch_time_queue */
		run_command("sudo tc qdisc replace dev %s parent 8001:%d etf offload clockid CLOCK_TAI delta 500000",
			    ifname, launch_time_queue + 1);
		sleep(1);

		/* Route incoming packet with VLAN priority 1 into launch_time_queue */
		if (run_command("sudo ethtool -N %s flow-type ether vlan 0x2000 vlan-mask 0x1FFF action %d",
				ifname, launch_time_queue)) {
			run_command("sudo tc qdisc add dev %s ingress", ifname);
			run_command("sudo tc filter add dev %s parent ffff: protocol 802.1Q flower vlan_prio 1 hw_tc %d",
				    ifname, launch_time_queue);
		}

		/* Enable VLAN tag stripping offload */
		run_command("sudo ethtool -K %s rxvlan on", ifname);
	}

	rx_xsk = malloc(sizeof(struct xsk) * rxq);
	if (!rx_xsk)
		error(1, ENOMEM, "malloc");

	for (i = 0; i < rxq; i++) {
		printf("open_xsk(%s, %p, %d)\n", ifname, &rx_xsk[i], i);
		ret = open_xsk(ifindex, &rx_xsk[i], i);
		if (ret)
			error(1, -ret, "open_xsk");

		printf("xsk_socket__fd() -> %d\n", xsk_socket__fd(rx_xsk[i].socket));
	}

	printf("open bpf program...\n");
	bpf_obj = xdp_hw_metadata__open();
	if (libbpf_get_error(bpf_obj))
		error(1, libbpf_get_error(bpf_obj), "xdp_hw_metadata__open");

	prog = bpf_object__find_program_by_name(bpf_obj->obj, "rx");
	bpf_program__set_ifindex(prog, ifindex);
	bpf_program__set_flags(prog, BPF_F_XDP_DEV_BOUND_ONLY);

	printf("load bpf program...\n");
	ret = xdp_hw_metadata__load(bpf_obj);
	if (ret)
		error(1, -ret, "xdp_hw_metadata__load");

	printf("prepare skb endpoint...\n");
	server_fd = start_server(AF_INET6, SOCK_DGRAM, NULL, 9092, 1000);
	if (server_fd < 0)
		error(1, errno, "start_server");
	timestamping_enable(server_fd,
			    SOF_TIMESTAMPING_SOFTWARE |
			    SOF_TIMESTAMPING_RAW_HARDWARE);

	printf("prepare xsk map...\n");
	for (i = 0; i < rxq; i++) {
		int sock_fd = xsk_socket__fd(rx_xsk[i].socket);
		__u32 queue_id = i;

		printf("map[%d] = %d\n", queue_id, sock_fd);
		ret = bpf_map_update_elem(bpf_map__fd(bpf_obj->maps.xsk), &queue_id, &sock_fd, 0);
		if (ret)
			error(1, -ret, "bpf_map_update_elem");
	}

	printf("attach bpf program...\n");
	ret = bpf_xdp_attach(ifindex,
			     bpf_program__fd(bpf_obj->progs.rx),
			     XDP_FLAGS, NULL);
	if (ret)
		error(1, -ret, "bpf_xdp_attach");

	signal(SIGINT, handle_signal);
	ret = verify_metadata(rx_xsk, rxq, server_fd, clock_id);
	close(server_fd);
	cleanup();
	if (ret)
		error(1, -ret, "verify_metadata");

	clean_existing_configurations();

free_mem:
	free(buf);
	free(map);
	free(que);
}
