// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * lagblame: per-app lag attribution.
 *
 *   scheduler   runqueue delay of the watched apps' threads (wakeup -> on CPU)
 *   UDP         send/receive rhythm per socket, NIC -> socket -> app timing
 *   TCP         smoothed RTT + retransmits on the apps' sockets
 *   kernel      NET_RX/NET_TX softirq latency, skb drops by reason
 *
 * Everything is aggregated in per-CPU maps that user space swaps every tick
 * (parity), plus a ring buffer of individual spikes above the thresholds.
 */
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "lagblame.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define NSEC 1000000000ULL
#define FLOW_IDLE_NS (5 * NSEC)	/* longer gaps = the flow was idle, not a stall */
#define FLOW_WARMUP 32		/* packets before gaps count */
#define SKB_TTL_NS (NSEC / 5)

const volatile __u64 rq_thresh_ns = 4000000;
const volatile __u64 gap_thresh_ns = 50000000;
const volatile __u64 pickup_thresh_ns = 4000000;
const volatile __u64 stack_thresh_ns = 2000000;
const volatile __u64 sirq_thresh_ns = 2000000;

/* flipped by user space each tick: BPF writes to [parity], user space drains the other half */
__u32 parity = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);	/* tgid */
	__type(value, __u32);	/* slot */
} targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);	/* tid */
	__type(value, __u64);	/* runnable since */
} runnable SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_SLOTS * 2);
	__type(key, __u32);
	__type(value, struct slot_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct glob_stats);
} gstats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct drop_counts);
} drops SEC(".maps");

/* ifindexes of tunnel interfaces (tun, wireguard), filled by user space */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} tunifs SEC(".maps");

/* per-CPU softirq timestamps: index 0..1 raise, 2..3 entry ([0]=NET_TX) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} sirq_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);	/* struct sock * */
	__type(value, struct flow);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);	/* struct sk_buff * */
	__type(value, struct skb_seen);
} skbs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} events SEC(".maps");

static __always_inline __u32 cur_parity(void)
{
	return *(volatile __u32 *)&parity & 1;
}

static __always_inline int slot_of(__u32 tgid)
{
	__u32 *s = bpf_map_lookup_elem(&targets, &tgid);

	return s ? (int)*s : -1;
}

static __always_inline struct slot_stats *slot_stats(__u32 slot)
{
	__u32 key;

	if (slot >= MAX_SLOTS)
		return NULL;
	key = slot * 2 + cur_parity();
	return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline void put_max(__u64 *m, __u64 v)
{
	if (v > *m)
		*m = v;
}

static __always_inline __u32 log2_u64(__u64 v)
{
	__u32 r = 0;

	if (v >> 32) { v >>= 32; r += 32; }
	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8) { v >>= 8; r += 8; }
	if (v >> 4) { v >>= 4; r += 4; }
	if (v >> 2) { v >>= 2; r += 2; }
	if (v >> 1) { r += 1; }
	return r;
}

static __always_inline struct event *ev_new(__u32 kind, __u32 slot, __u64 value)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	__u64 id;

	if (!e)
		return NULL;
	__builtin_memset(e, 0, sizeof(*e));
	id = bpf_get_current_pid_tgid();
	e->ts = bpf_ktime_get_ns();
	e->kind = kind;
	e->slot = slot;
	e->value = value;
	e->tgid = id >> 32;
	e->tid = (__u32)id;
	e->cpu = bpf_get_smp_processor_id();
	return e;
}

static __always_inline void ev_flow(struct event *e, struct flow *f)
{
	e->tgid = f->tgid;
	e->rport = f->rport;
	e->family = f->family;
	__builtin_memcpy(e->raddr, f->raddr, 16);
}

/* ---------------------------------------------------------------- sched */

static __always_inline unsigned int task_state(struct task_struct *t)
{
	if (bpf_core_field_exists(t->__state))
		return t->__state;
	return BPF_CORE_READ((struct task_struct___old *)t, state);
}

static __always_inline int mark_runnable(struct task_struct *p)
{
	__u32 tid;
	__u64 ts;

	/* tp_btf task pointers are trusted: direct (CO-RE relocated) loads, no helper calls */
	if (slot_of(p->tgid) < 0)
		return 0;
	tid = p->pid;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&runnable, &tid, &ts, BPF_ANY);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_wakeup, struct task_struct *p)
{
	return mark_runnable(p);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(on_wakeup_new, struct task_struct *p)
{
	return mark_runnable(p);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct slot_stats *st;
	struct event *e;
	__u64 now, *since, d;
	__u32 tid, b;
	int slot;

	/* preempted while runnable: it is back on the runqueue */
	if (task_state(prev) == 0)
		mark_runnable(prev);

	slot = slot_of(next->tgid);
	if (slot < 0)
		return 0;
	tid = next->pid;
	since = bpf_map_lookup_elem(&runnable, &tid);
	if (!since)
		return 0;
	now = bpf_ktime_get_ns();
	d = now - *since;
	bpf_map_delete_elem(&runnable, &tid);
	if (d > 10 * NSEC)
		return 0;

	st = slot_stats(slot);
	if (st) {
		st->rq_cnt++;
		st->rq_sum += d;
		put_max(&st->rq_max, d);
		b = log2_u64(d / 1000);
		if (b >= RQ_BUCKETS)
			b = RQ_BUCKETS - 1;
		st->rq_hist[b]++;
	}
	if (d < rq_thresh_ns)
		return 0;
	e = ev_new(EV_RQ, slot, d);
	if (!e)
		return 0;
	e->tgid = next->tgid;
	e->tid = tid;
	e->other_pid = prev->pid;
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), next->comm);
	bpf_probe_read_kernel_str(e->other_comm, sizeof(e->other_comm), prev->comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------------------------------------------------------- flows */

static __always_inline void flow_addr_from_sock(struct flow *f, struct sock *sk)
{
	__u16 fam = BPF_CORE_READ(sk, __sk_common.skc_family);
	__be32 a4;

	f->family = fam;
	f->rport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (fam == AF_INET) {
		a4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(f->raddr, &a4, 4);
	} else if (fam == AF_INET6) {
		BPF_CORE_READ_INTO(&f->raddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

/* flow of a socket used by a watched app; created on first use */
static __always_inline struct flow *flow_get(struct sock *sk, int slot, __u32 tgid, __u8 proto)
{
	__u64 key = (__u64)sk;
	struct flow *f = bpf_map_lookup_elem(&flows, &key);
	struct flow nf = {};

	if (f)
		return f;
	nf.slot = slot;
	nf.tgid = tgid;
	nf.proto = proto;
	flow_addr_from_sock(&nf, sk);
	bpf_map_update_elem(&flows, &key, &nf, BPF_NOEXIST);
	return bpf_map_lookup_elem(&flows, &key);
}

/* gap since the last packet on a steady flow; returns the gap or 0 */
static __always_inline __u64 flow_gap(__u64 now, __u64 *last, __u64 *ewma, __u64 pkts)
{
	__u64 gap = 0;

	if (*last && now > *last) {
		gap = now - *last;
		if (gap > FLOW_IDLE_NS)
			gap = 0;
		else
			*ewma = *ewma - (*ewma >> 3) + (gap >> 3);
	}
	*last = now;
	if (pkts < FLOW_WARMUP)
		return 0;
	return gap;
}

static __always_inline int udp_send(struct sock *sk, struct msghdr *msg, size_t len)
{
	__u64 id = bpf_get_current_pid_tgid(), now, gap, ewma;
	__u32 tgid = id >> 32;
	struct slot_stats *st;
	struct flow *f;
	struct event *e;
	int slot = slot_of(tgid);
	void *name;

	if (slot < 0)
		return 0;
	f = flow_get(sk, slot, tgid, IPPROTO_UDP);
	if (!f)
		return 0;
	if (!f->rport) {
		/* unconnected socket: remember the last destination */
		name = BPF_CORE_READ(msg, msg_name);
		if (name) {
			struct sockaddr_in6 sa = {};

			bpf_probe_read_kernel(&sa, sizeof(sa), name);
			if (sa.sin6_family == AF_INET) {
				struct sockaddr_in *s4 = (void *)&sa;

				f->family = AF_INET;
				f->rport = __builtin_bswap16(s4->sin_port);
				__builtin_memcpy(f->raddr, &s4->sin_addr, 4);
			} else if (sa.sin6_family == AF_INET6) {
				f->family = AF_INET6;
				f->rport = __builtin_bswap16(sa.sin6_port);
				__builtin_memcpy(f->raddr, sa.sin6_addr, 16);
			}
		}
	}
	now = bpf_ktime_get_ns();
	ewma = f->ewma_tx;
	gap = flow_gap(now, &f->last_tx, &f->ewma_tx, f->tx_pkts);
	f->tx_pkts++;

	st = slot_stats(slot);
	if (st) {
		st->tx_pkts++;
		st->tx_bytes += len;
		put_max(&st->tx_gap_max, gap);
	}
	if (gap >= gap_thresh_ns && gap > 4 * ewma) {
		e = ev_new(EV_TX_GAP, slot, gap);
		if (e) {
			ev_flow(e, f);
			bpf_get_current_comm(e->comm, sizeof(e->comm));
			bpf_ringbuf_submit(e, 0);
		}
	}
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_send, struct sock *sk, struct msghdr *msg, size_t len)
{
	return udp_send(sk, msg, len);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(on_udp6_send, struct sock *sk, struct msghdr *msg, size_t len)
{
	return udp_send(sk, msg, len);
}

/* first time the stack saw a UDP skb (and the second time, after an in-kernel tunnel) */
SEC("tp_btf/netif_receive_skb")
int BPF_PROG(on_netif_rx, struct sk_buff *skb)
{
	__u16 proto = __builtin_bswap16(BPF_CORE_READ(skb, protocol));
	unsigned char *data = BPF_CORE_READ(skb, data);
	__u64 key = (__u64)skb, now;
	struct skb_seen *s, ns = {};
	__u8 l4 = 0;
	__u32 ifi;

	if (proto == 0x0800)
		bpf_probe_read_kernel(&l4, 1, data + 9);
	else if (proto == 0x86DD)
		bpf_probe_read_kernel(&l4, 1, data + 6);
	if (l4 != IPPROTO_UDP)
		return 0;
	ifi = BPF_CORE_READ(skb, dev, ifindex);
	now = bpf_ktime_get_ns();
	s = bpf_map_lookup_elem(&skbs, &key);
	if (s && s->last_if != ifi && now - s->last_ts < SKB_TTL_NS && !s->enq_ts) {
		s->last_if = ifi;
		s->last_ts = now;
		return 0;
	}
	ns.first_ts = ns.last_ts = now;
	ns.first_if = ns.last_if = ifi;
	bpf_map_update_elem(&skbs, &key, &ns, BPF_ANY);
	return 0;
}

SEC("fentry/__udp_enqueue_schedule_skb")
int BPF_PROG(on_udp_enqueue, struct sock *sk, struct sk_buff *skb)
{
	__u64 key = (__u64)sk, skey = (__u64)skb, now, gap, ewma, d;
	struct slot_stats *st;
	struct skb_seen *s;
	struct flow *f;
	struct event *e;

	f = bpf_map_lookup_elem(&flows, &key);
	if (!f) {
		bpf_map_delete_elem(&skbs, &skey);
		return 0;
	}
	now = bpf_ktime_get_ns();
	ewma = f->ewma_rx;
	gap = flow_gap(now, &f->last_rx, &f->ewma_rx, f->rx_pkts);
	f->rx_pkts++;
	st = slot_stats(f->slot);
	if (!st)
		return 0;
	st->rx_pkts++;
	st->rx_bytes += BPF_CORE_READ(skb, len);
	put_max(&st->rx_gap_max, gap);
	if (gap >= gap_thresh_ns && gap > 4 * ewma) {
		e = ev_new(EV_RX_GAP, f->slot, gap);
		if (e) {
			ev_flow(e, f);
			e->tid = 0;
			bpf_ringbuf_submit(e, 0);
		}
	}

	s = bpf_map_lookup_elem(&skbs, &skey);
	if (!s) {
		struct skb_seen ns = { .enq_ts = now };

		bpf_map_update_elem(&skbs, &skey, &ns, BPF_ANY);
		return 0;
	}
	s->enq_ts = now;
	f->rx_if = s->last_if;
	if (bpf_map_lookup_elem(&tunifs, &s->last_if))
		st->rx_tun_pkts++;
	if (!s->first_ts || now < s->first_ts || now - s->first_ts > SKB_TTL_NS)
		return 0;
	d = now - s->first_ts;
	st->stack_cnt++;
	st->stack_sum += d;
	put_max(&st->stack_max, d);
	if (s->last_if != s->first_if) {
		__u64 t = s->last_ts - s->first_ts;

		st->tun_cnt++;
		st->tun_sum += t;
		put_max(&st->tun_max, t);
		if (t >= stack_thresh_ns) {
			e = ev_new(EV_TUNNEL, f->slot, t);
			if (e) {
				ev_flow(e, f);
				e->aux = s->last_if;
				bpf_ringbuf_submit(e, 0);
			}
		}
	}
	if (d >= stack_thresh_ns) {
		e = ev_new(EV_STACK, f->slot, d);
		if (e) {
			ev_flow(e, f);
			e->aux = s->first_if;
			bpf_ringbuf_submit(e, 0);
		}
	}
	return 0;
}

/* the app took the packet out of the socket */
SEC("fentry/skb_consume_udp")
int BPF_PROG(on_udp_consume, struct sock *sk, struct sk_buff *skb, int len)
{
	__u64 skey = (__u64)skb, key = (__u64)sk, now, d;
	struct slot_stats *st;
	struct skb_seen *s;
	struct flow *f;
	struct event *e;

	s = bpf_map_lookup_elem(&skbs, &skey);
	if (!s)
		return 0;
	if (!s->enq_ts)
		goto out;
	f = bpf_map_lookup_elem(&flows, &key);
	if (!f)
		goto out;
	now = bpf_ktime_get_ns();
	if (now < s->enq_ts)
		goto out;
	d = now - s->enq_ts;
	st = slot_stats(f->slot);
	if (st) {
		st->pick_cnt++;
		st->pick_sum += d;
		put_max(&st->pick_max, d);
	}
	if (d >= pickup_thresh_ns) {
		e = ev_new(EV_PICKUP, f->slot, d);
		if (e) {
			ev_flow(e, f);
			bpf_get_current_comm(e->comm, sizeof(e->comm));
			bpf_ringbuf_submit(e, 0);
		}
	}
out:
	bpf_map_delete_elem(&skbs, &skey);
	return 0;
}

SEC("tp_btf/udp_fail_queue_rcv_skb")
int BPF_PROG(on_udp_fail, int rc, struct sock *sk)
{
	__u64 key = (__u64)sk;
	struct slot_stats *st;
	struct flow *f = bpf_map_lookup_elem(&flows, &key);
	struct event *e;

	if (!f)
		return 0;
	st = slot_stats(f->slot);
	if (st)
		st->rcvbuf_drops++;
	e = ev_new(EV_RCVBUF_DROP, f->slot, 0);
	if (e) {
		ev_flow(e, f);
		e->aux = -rc;
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}

/* forget the socket when it goes away (pointers get reused) */
SEC("fentry/inet_sock_destruct")
int BPF_PROG(on_sock_destruct, struct sock *sk)
{
	__u64 key = (__u64)sk;

	bpf_map_delete_elem(&flows, &key);
	return 0;
}

/* ---------------------------------------------------------------- TCP */

static __always_inline int tcp_track(struct sock *sk)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	int slot = slot_of(tgid);

	if (slot >= 0)
		flow_get(sk, slot, tgid, IPPROTO_TCP);
	return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_tcp_send, struct sock *sk)
{
	return tcp_track(sk);
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(on_tcp_recv, struct sock *sk)
{
	return tcp_track(sk);
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(on_tcp_rcv, struct sock *sk)
{
	__u64 key = (__u64)sk;
	struct flow *f = bpf_map_lookup_elem(&flows, &key);
	struct slot_stats *st;
	__u64 srtt;

	if (!f)
		return 0;
	st = slot_stats(f->slot);
	if (!st)
		return 0;
	srtt = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us) >> 3;
	st->srtt_cnt++;
	st->srtt_sum += srtt;
	put_max(&st->srtt_max, srtt);
	f->rx_pkts++;
	return 0;
}

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(on_tcp_retrans, struct sock *sk)
{
	__u64 key = (__u64)sk;
	struct flow *f = bpf_map_lookup_elem(&flows, &key);
	struct slot_stats *st;
	struct event *e;

	if (!f)
		return 0;
	st = slot_stats(f->slot);
	if (st)
		st->tcp_retrans++;
	e = ev_new(EV_TCP_RETRANS, f->slot, BPF_CORE_READ((struct tcp_sock *)sk, srtt_us) >> 3);
	if (e) {
		ev_flow(e, f);
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}

/* ---------------------------------------------------------------- kernel */

#define NET_TX_SOFTIRQ 2
#define NET_RX_SOFTIRQ 3

SEC("tp_btf/softirq_raise")
int BPF_PROG(on_sirq_raise, unsigned int vec)
{
	__u32 k;
	__u64 *t;

	if (vec != NET_TX_SOFTIRQ && vec != NET_RX_SOFTIRQ)
		return 0;
	k = (vec == NET_RX_SOFTIRQ) & 1;
	t = bpf_map_lookup_elem(&sirq_ts, &k);
	if (t && !*t)
		*t = bpf_ktime_get_ns();
	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(on_sirq_entry, unsigned int vec)
{
	__u32 k, ke, g = cur_parity();
	struct glob_stats *gs;
	struct event *e;
	__u64 *t, *te, now, d;

	if (vec != NET_TX_SOFTIRQ && vec != NET_RX_SOFTIRQ)
		return 0;
	k = (vec == NET_RX_SOFTIRQ) & 1;
	ke = k + 2;
	now = bpf_ktime_get_ns();
	te = bpf_map_lookup_elem(&sirq_ts, &ke);
	if (te)
		*te = now;
	t = bpf_map_lookup_elem(&sirq_ts, &k);
	if (!t || !*t)
		return 0;
	d = now - *t;
	*t = 0;
	gs = bpf_map_lookup_elem(&gstats, &g);
	if (!gs)
		return 0;
	barrier_var(k);
	k &= 1;
	gs->sirq_cnt[k]++;
	gs->sirq_lat_sum[k] += d;
	put_max(&gs->sirq_lat_max[k], d);
	if (d >= sirq_thresh_ns && d < NSEC) {
		e = ev_new(EV_SOFTIRQ, MAX_SLOTS, d);
		if (e) {
			e->aux = vec;
			bpf_get_current_comm(e->comm, sizeof(e->comm));
			bpf_ringbuf_submit(e, 0);
		}
	}
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(on_sirq_exit, unsigned int vec)
{
	__u32 ke, g = cur_parity(), k;
	struct glob_stats *gs;
	__u64 *te, d;

	if (vec != NET_TX_SOFTIRQ && vec != NET_RX_SOFTIRQ)
		return 0;
	k = (vec == NET_RX_SOFTIRQ) & 1;
	ke = k + 2;
	te = bpf_map_lookup_elem(&sirq_ts, &ke);
	if (!te || !*te)
		return 0;
	d = bpf_ktime_get_ns() - *te;
	*te = 0;
	gs = bpf_map_lookup_elem(&gstats, &g);
	if (!gs)
		return 0;
	barrier_var(k);
	k &= 1;
	gs->sirq_dur_sum[k] += d;
	put_max(&gs->sirq_dur_max[k], d);
	return 0;
}

SEC("tp_btf/kfree_skb")
int BPF_PROG(on_kfree_skb, struct sk_buff *skb, void *location, int reason)
{
	__u32 k = (__u32)reason, g = cur_parity();
	__u64 skey = (__u64)skb, key;
	struct drop_counts *dc;
	struct slot_stats *st;
	struct sock *sk;
	struct flow *f;
	struct event *e;

	if (k >= MAX_REASONS)
		k = MAX_REASONS - 1;
	dc = bpf_map_lookup_elem(&drops, &g);
	barrier_var(k);
	k &= MAX_REASONS - 1;
	if (dc)
		dc->n[k]++;
	bpf_map_delete_elem(&skbs, &skey);

	sk = BPF_CORE_READ(skb, sk);
	if (!sk)
		return 0;
	key = (__u64)sk;
	f = bpf_map_lookup_elem(&flows, &key);
	if (!f)
		return 0;
	st = slot_stats(f->slot);
	if (st)
		st->skb_drops++;
	e = ev_new(EV_SKB_DROP, f->slot, 0);
	if (e) {
		ev_flow(e, f);
		e->aux = (__u32)reason;
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}
