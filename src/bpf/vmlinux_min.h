/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Just the kernel types lagblame reads. Every struct is marked
 * preserve_access_index, so libbpf relocates the field offsets against the
 * running kernel's BTF (CO-RE): no full vmlinux.h, any kernel with BTF works.
 */
#ifndef LAGBLAME_VMLINUX_MIN_H
#define LAGBLAME_VMLINUX_MIN_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef _Bool bool;
typedef unsigned long size_t;
#define true 1
#define false 0
#define NULL ((void *)0)

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

struct task_struct {
	int pid;
	int tgid;
	char comm[16];
	unsigned int __state;
};

/* kernels before 5.14 call it "state" */
struct task_struct___old {
	long state;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
};

struct sock_common {
	__be32 skc_daddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
};

struct sock {
	struct sock_common __sk_common;
};

struct tcp_sock {
	__u32 srtt_us;
};

struct net_device {
	int ifindex;
};

struct sk_buff {
	struct net_device *dev;
	struct sock *sk;
	unsigned int len;
	__be16 protocol;
	unsigned char *data;
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
};

#pragma clang attribute pop

struct sockaddr_in {
	unsigned short sin_family;
	__be16 sin_port;
	__be32 sin_addr;
	unsigned char pad[8];
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	__u8 sin6_addr[16];
	__u32 sin6_scope_id;
};

#endif
