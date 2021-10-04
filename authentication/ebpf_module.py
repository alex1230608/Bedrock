#!/usr/bin/python
#
# strlen_count  Trace strlen() and print a frequency count of strings.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of BCC and uprobes.
#
# Also see strlensnoop.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep
import socket
import argparse

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#define IBV_QP_DEST_QPN (1 << 20)
#define IBV_QP_AV       (1 << 7)

struct ibv_qp {
        void                 *context;
        void                   *qp_context;
        void         *pd;
        void         *send_cq;
        void         *recv_cq;
        void           *srq;
        uint32_t                handle;
        uint32_t                qp_num;
};
struct ibv_qp_cap {
	uint32_t		max_send_wr;
	uint32_t		max_recv_wr;
	uint32_t		max_send_sge;
	uint32_t		max_recv_sge;
	uint32_t		max_inline_data;
};
union ibv_gid {
	uint8_t			raw[16];
	struct {
		__be64	subnet_prefix;
		__be64	interface_id;
	} global;
};
struct ibv_global_route {
	union ibv_gid		dgid;
	uint32_t		flow_label;
	uint8_t			sgid_index;
	uint8_t			hop_limit;
	uint8_t			traffic_class;
};
struct ibv_ah_attr {
	struct ibv_global_route	grh;
	uint16_t		dlid;
	uint8_t			sl;
	uint8_t			src_path_bits;
	uint8_t			static_rate;
	uint8_t			is_global;
	uint8_t			port_num;
};
struct ibv_qp_attr {
	int                     qp_state;
	int                     cur_qp_state;
	int                     path_mtu;
	int               	path_mig_state;
	uint32_t		qkey;
	uint32_t		rq_psn;
	uint32_t		sq_psn;
	uint32_t		dest_qp_num;
	unsigned int		qp_access_flags;
	struct ibv_qp_cap	cap;
	struct ibv_ah_attr	ah_attr;
	// struct ibv_ah_attr	alt_ah_attr;
	// uint16_t		pkey_index;
	// uint16_t		alt_pkey_index;
	// uint8_t			en_sqd_async_notify;
	// uint8_t			sq_draining;
	// uint8_t			max_rd_atomic;
	// uint8_t			max_dest_rd_atomic;
	// uint8_t			min_rnr_timer;
	// uint8_t			port_num;
	// uint8_t			timeout;
	// uint8_t			retry_cnt;
	// uint8_t			rnr_retry;
	// uint8_t			alt_port_num;
	// uint8_t			alt_timeout;
	// uint32_t		rate_limit;
};

// union key_t {
//     u32 val;
//     char raw[4];
// };
// BPF_HASH(dqpnToEncoded, union key_t);
// BPF_HASH(encodedToDqpn, union key_t);

// for server
struct data_t {
    u32 dip;
    u32 qpn;
    u32 dqpn;
};
BPF_PERF_OUTPUT(events);

// for client
BPF_HASH(qpn_pid, u32, u32);

int get_dip_dqpn_signal_switch(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx) || !PT_REGS_PARM3(ctx))
        return 0;

    // u64 zero = 0, *val;

    struct ibv_qp qp;
    struct ibv_qp_attr attr = {0};
    bpf_probe_read_user(&qp, sizeof(qp), (void *) PT_REGS_PARM1(ctx));
    bpf_probe_read_user(&attr, sizeof(attr), (void *) PT_REGS_PARM2(ctx));
    int attr_mask = PT_REGS_PARM3(ctx);

    // TODO: for now, we assume dst IP and DQPN are always modified together
    if ((attr_mask & IBV_QP_DEST_QPN) == 0 && (attr_mask & IBV_QP_AV) == 0)
        return 0;
    else if ((attr_mask & IBV_QP_DEST_QPN) == 0 || (attr_mask & IBV_QP_AV) == 0) {
        bpf_trace_printk(\"Error\\n\");
        return 0;
    }

    struct data_t data;
    bpf_trace_printk(\"interface_id: %lx\\n\",
        attr.ah_attr.grh.dgid.global.interface_id);
    data.dip = (attr.ah_attr.grh.dgid.global.interface_id >> 32);
    data.qpn = qp.qp_num;
    data.dqpn = attr.dest_qp_num;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int add_qpn_to_pid(struct pt_regs *ctx) {
    if (!PT_REGS_RC(ctx))
        return 0;

    struct ibv_qp qp;
    bpf_probe_read_user(&qp, sizeof(qp), (void *) PT_REGS_RC(ctx));
    u32 pid = bpf_get_current_pid_tgid();

    u32* pidp;
    pidp = qpn_pid.lookup(&qp.qp_num);
    if (pidp != 0) {
        bpf_trace_printk(\"qpn already exists, we overwrite it with the new one\\n\");
    }
    qpn_pid.update(&qp.qp_num, &pid);
    bpf_trace_printk(\"In the add_qpn_to_pid function. qp_num, pid: %d, %d\\n\", qp.qp_num, pid);

    // if ((attr_mask & IBV_QP_DEST_QPN) == 0)
    //     return 0;

    // uint32_t original = attr.dest_qp_num;
    // attr.dest_qp_num ^= qp.qp_num;
    // bpf_probe_write_user((void *) PT_REGS_PARM2(ctx), &attr, sizeof(attr));

    // bpf_trace_printk(\"Original dqpn: %lu, Modified dqpn: %lu\\n\", original, attr.dest_qp_num);

    return 0;
};

int modify_dqpn(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx) || !PT_REGS_PARM3(ctx))
        return 0;

    // u64 zero = 0, *val;

    struct ibv_qp qp;
    bpf_probe_read_user(&qp, sizeof(qp), (void *) PT_REGS_PARM1(ctx));
    struct ibv_qp_attr attr = {0};

    u32* pidp;
    pidp = qpn_pid.lookup(&qp.qp_num);
    u32 pid = bpf_get_current_pid_tgid();
    if (pidp == 0) {
        bpf_trace_printk(\"qpn never created, either a mistake or an attack\\n\");
        // we zero out the attr values to avoid any further modification
        bpf_probe_write_user((void *) PT_REGS_PARM2(ctx), &attr, sizeof(attr));

    } else if (*pidp != pid) {
        bpf_trace_printk(\"pid mismatched, either a mistake or an attack\\n\");
        // we zero out the attr values to avoid any further modification
        bpf_probe_write_user((void *) PT_REGS_PARM2(ctx), &attr, sizeof(attr));
    } else {
        bpf_probe_read_user(&attr, sizeof(attr), (void *) PT_REGS_PARM2(ctx));

        int attr_mask = PT_REGS_PARM3(ctx);

        // bpf_trace_printk(\"In the modify_dqpn function. attr_mask: %d\\n\", attr_mask);

        if ((attr_mask & IBV_QP_DEST_QPN) == 0) {
            return 0;
        }
        
        uint32_t original = attr.dest_qp_num;
        attr.dest_qp_num = qp.qp_num;
        bpf_probe_write_user((void *) PT_REGS_PARM2(ctx), &attr, sizeof(attr));

        bpf_trace_printk(\"Original dqpn: %lu, Modified dqpn: %lu\\n\", original, attr.dest_qp_num);
    }

    // union key_t k;
    // k.val = qp.qp_num;
    // val = counts.lookup_or_try_init(&k, &zero);
    // if (val) {
    //   (*val)++;
    //   bpf_trace_printk(\"%llu: post send, QPN: %lu\\n\", *val, qp.qp_num);
    //   qp.qp_num++;
    //   bpf_probe_write_user((void *) PT_REGS_PARM1(ctx), &qp, sizeof(qp));
    // }

    return 0;
};

""")

def reverse_endian(num):
   return ((num>>24)&0xff) | ((num>>8)&0xff00) | ((num<<8)&0xff0000) | ((num<<24)&0xff000000)

def send_to_switch(dip, dqpn, qpn):
    UDP_IP = socket.inet_ntop(socket.AF_INET, dip.to_bytes(4, 'big'))
    UDP_PORT = 12349
    to_send = dip.to_bytes(4, 'big') + dqpn.to_bytes(3, 'big') + qpn.to_bytes(3, 'big')
    # to_send = bytearray(dip.to_bytes(4, 'big'))
    # to_send.append(bytearray(dqpn.to_bytes(3, 'big')))
    # to_send.append(bytearray(qpn.to_bytes(3, 'big')))
    
    print("UDP target IP: %s" % UDP_IP)
    print("UDP target port: %s" % UDP_PORT)
    print(bytes(to_send).hex())
    
    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.sendto(to_send, (UDP_IP, UDP_PORT))

# process event
def process_event(cpu, data, size):
    event = b["events"].event(data)
    dip = reverse_endian(event.dip)
    print("%08x %d %d" % (dip, event.dqpn, event.qpn))
    send_to_switch(dip, event.dqpn, event.qpn)

def main(args):
   if args.isServer == 1:
       b.attach_uprobe(name="mlx5", sym="mlx5_modify_qp", fn_name="get_dip_dqpn_signal_switch")
   else:
       b.attach_uretprobe(name="mlx5", sym="mlx5_create_qp", fn_name="add_qpn_to_pid")
       b.attach_uprobe(name="mlx5", sym="mlx5_modify_qp", fn_name="modify_dqpn")
   
   
   # header
   print("Tracing mlx5_modify_qp(), mlx5_create_qp()... Hit Ctrl-C to end.")
   
   if args.isServer == 1:
       # loop with callback to print_event
       b["events"].open_perf_buffer(process_event)
       while 1:
           try:
               b.perf_buffer_poll()
           except KeyboardInterrupt:
               exit()
   
   else:
       # sleep until Ctrl-C
       try:
           sleep(99999999)
       except KeyboardInterrupt:
           pass
   
   # # print output
   # print("%10s %s" % ("COUNT", "STRING"))
   # counts = b.get_table("counts")
   # for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
   #     printb(b"%10d \"%d\"" % (v.value, k.val))

if __name__ == "__main__":
   parser = argparse.ArgumentParser(description = 'Secured module on server/client')
   parser.add_argument('-s', dest='isServer', required=True, type=int, help='Is server or not')
   args = parser.parse_args()
   main(args)


