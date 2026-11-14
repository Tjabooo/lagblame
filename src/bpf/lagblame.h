/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Shared between the BPF program and src/bpf.rs (keep both in sync). */
#ifndef LAGBLAME_H
#define LAGBLAME_H

#define MAX_SLOTS 32		/* watched apps (incl. tunnel daemons) */
#define RQ_BUCKETS 24		/* log2(us) histogram buckets */
#define MAX_REASONS 256		/* skb drop reasons */

enum ev_kind {
	EV_RQ = 1,		/* thread waited on the runqueue */
	EV_TX_GAP = 2,		/* app stopped sending on a busy flow */
	EV_RX_GAP = 3,		/* nothing arrived on a busy flow */
	EV_PICKUP = 4,		/* packet sat in the socket before the app read it */
	EV_STACK = 5,		/* NIC -> socket took long */
	EV_TUNNEL = 6,		/* in-kernel tunnel (wireguard) decap took long */
	EV_SOFTIRQ = 7,		/* NET_RX/NET_TX softirq ran late */
	EV_RCVBUF_DROP = 8,	/* socket buffer full, packet dropped */
	EV_SKB_DROP = 9,	/* kernel dropped one of the app's packets */
	EV_TCP_RETRANS = 10,	/* TCP retransmit */
};

struct slot_stats {
	__u64 rq_cnt, rq_sum, rq_max;
	__u64 rq_hist[RQ_BUCKETS];
	__u64 tx_pkts, tx_bytes, rx_pkts, rx_bytes;
	__u64 tx_gap_max, rx_gap_max;
	__u64 stack_cnt, stack_sum, stack_max;
	__u64 tun_cnt, tun_sum, tun_max;
	__u64 pick_cnt, pick_sum, pick_max;
	__u64 rcvbuf_drops, skb_drops, tcp_retrans;
	__u64 rx_tun_pkts;		/* arrived through a tunnel interface */
	__u64 srtt_cnt, srtt_sum, srtt_max;	/* us */
};

/* [0] = NET_TX, [1] = NET_RX */
struct glob_stats {
	__u64 sirq_cnt[2], sirq_lat_sum[2], sirq_lat_max[2];
	__u64 sirq_dur_sum[2], sirq_dur_max[2];
};

struct drop_counts {
	__u64 n[MAX_REASONS];
};

struct event {
	__u64 ts;		/* CLOCK_MONOTONIC ns */
	__u64 value;		/* ns (or srtt us for retrans) */
	__u32 kind;
	__u32 slot;
	__u32 tgid;
	__u32 tid;
	__u32 cpu;
	__u32 other_pid;	/* EV_RQ: task that ran on the CPU just before */
	__u32 aux;		/* drop reason / ifindex / softirq vec */
	__u16 rport;
	__u16 family;
	__u8 raddr[16];
	char comm[16];
	char other_comm[16];
};

struct flow {
	__u64 last_tx, last_rx;
	__u64 ewma_tx, ewma_rx;	/* ns between packets, 1/8 smoothing */
	__u64 tx_pkts, rx_pkts;
	__u32 slot, tgid;
	__u32 rx_if;
	__u16 rport, family;
	__u8 raddr[16];
	__u8 proto, pad[7];
};

struct skb_seen {
	__u64 first_ts, last_ts, enq_ts;
	__u32 first_if, last_if;
};

#endif
