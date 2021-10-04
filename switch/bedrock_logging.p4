/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This is P4 sample source for basic_switching

#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>

#define CURSOR_WIDTH 8    // 8 < 2^8
#define LOG_SIZE_MINUS1 7 // 8 logs per packet
#define LOG_HEADER_LEN 128

// Following consts are for document and not used in the program
#define RECORD_SIZE 16  // 16-byte log
//#define ETHER_ADDR_LOG 0x506b4b42d824
//#define IP_ADDR_LOG 0x0a000802
//#define ETHER_ADDR_LOG 0x506b4b4ba8a2
//#define IP_ADDR_LOG 0x0a000805
#define ETHER_ADDR_LOG 0xd8c497724b55
#define IP_ADDR_LOG 0x0a000806

#include "includes/headers.p4"
#include "includes/parser.p4"


action nop() {
}

action _drop() {
    drop();
}

/*===============================================================================================*/
/* Receive control message (so far for logging server's side channel attack alarm) */

field_list digest_fields {
    md.digest_type;

    ctrl.banned_dqpn;
    ipv4.dstAddr;
}

action send_entry_digest() {
    modify_field(md.digest_type, 2);
    generate_digest(0, digest_fields);
    drop();
    exit();
}

table receive_ctrl{
    actions {
        send_entry_digest;
    }
    default_action : send_entry_digest;
}

/*===============================================================================================*/
/* Banning ACL */

action drop_exit() {
    drop();
    exit();
}

table ban_acl {
    reads {
        ib_bth       : valid;
        ipv4.dstAddr : exact;
        ib_bth.dqpn  : exact;
    }
    actions {
        drop_exit;
        nop;
    }
    default_action: nop;
    size : 32768;
}

/*===============================================================================================*/
/* obtain timestamps */

// Use high 32-bit tstamp of the full 48 bits
field_list tstamp {
    _ingress_global_tstamp_;
}

field_list_calculation tstamp_high32 {
    input {
        tstamp;
    }
    algorithm : identity_msb;
    output_width : 32;
}

action split_tstamp_high32 () {
    modify_field_with_hash_based_offset(md.tstamp, 0, tstamp_high32, 0x100000000);
}

table split_tstamp_high32_tab {
    actions{
        split_tstamp_high32;
    }
    default_action : split_tstamp_high32;
}

/*===============================================================================================*/
/* the cursor for next request log */

register cursor {
    width          : CURSOR_WIDTH;
    instance_count : 1;
}

// read and update the cursor
blackbox stateful_alu read_update_cursor_alu {
    reg : cursor;

    condition_lo          : register_lo < LOG_SIZE_MINUS1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value     : register_lo + 1;

    update_lo_2_predicate : not condition_lo;
    update_lo_2_value     : 0;

    // output
    output_dst            : md.cursor;
    output_value          : register_lo;
}

action read_update_cursor () {
    read_update_cursor_alu.execute_stateful_alu(0);
}

table cursor_tab {
    actions {
        read_update_cursor;
    }
    default_action : read_update_cursor;
}

/*===============================================================================================*/
/* forwarding */
/* Multicast to log server if cursor == 0 */
/* Unicast otherwise */

#define GRP_BROADCAST 666

action set_mc(grp) {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, grp);
}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

table forward_reth {
    reads {
        md.cursor               : ternary;
        ipv4.dstAddr            : exact;
    }
    actions {
        set_egr; set_mc;
    }
    default_action: set_mc(GRP_BROADCAST);
}

table forward {
    reads {
        ipv4                    : valid;
        ipv4.dstAddr            : exact;
    }
    actions {
        set_egr; set_mc;
    }
    default_action : set_mc(GRP_BROADCAST);
}

/*===============================================================================================*/
/* Add log header */

action add_logHeader() {
    add_header(log_header);
    modify_field(udp.dstPort, UDP_PORT_LOG);
}

table add_logHeader_tab {
    reads {
        md.cursor : exact;
    }
    actions {
        add_logHeader;
        nop;
    }
    default_action : nop;
    size : 2;
}

/*===============================================================================================*/
/* Form log */

field_list log_byte0_fields {
    md.tstamp;
}
field_list log_byte4_fields {
    ib_bth.opCode;
    ib_bth.dqpn;
}
field_list log_byte8_fields {
    ib_reth.virtAddr_h;
    ib_reth.virtAddr_l;
}
field_list log_byte12_fields {
    ib_reth.virtAddr_l;
}

#define FORM_LOG(BYTE, POS)                                                                     \
field_list_calculation log_byte##BYTE {                                                         \
    input {                                                                                     \
        log_byte##BYTE##_fields;                                                                \
    }                                                                                           \
    algorithm : identity_##POS;                                                                 \
    output_width : 32;                                                                          \
}                                                                                               \
                                                                                                \
action form_log_byte##BYTE() {                                                                  \
    modify_field_with_hash_based_offset(md.log_byte##BYTE, 0, log_byte##BYTE, 0x100000000);     \
}                                                                                               \
                                                                                                \
table form_log_byte##BYTE##_tab {                                                               \
    actions{                                                                                    \
        form_log_byte##BYTE;                                                                    \
    }                                                                                           \
    default_action : form_log_byte##BYTE;                                                       \
}

FORM_LOG(0,  lsb)
FORM_LOG(4,  lsb)
FORM_LOG(8,  msb)
FORM_LOG(12, lsb)

/*===============================================================================================*/
/* Read and/or update logs */
/* Read the batch of log if cursor == 0 */
/* Update one log */

#define READ_UPDATE_LOG_BYTE(LOG, BYTE)                                                      \
register log##LOG##_byte##BYTE {                                                             \
    width          : 32;                                                                     \
    instance_count : 1;                                                                      \
}                                                                                            \
                                                                                             \
blackbox stateful_alu read_update_log##LOG##_byte##BYTE##_alu {                              \
    reg : log##LOG##_byte##BYTE;                                                             \
                                                                                             \
    condition_lo          : md.cursor == 0;                                                  \
    condition_hi          : md.cursor == LOG;                                                \
                                                                                             \
    update_lo_1_predicate : condition_hi;                                                    \
    update_lo_1_value     : md.log_byte##BYTE;                                               \
                                                                                             \
    output_predicate      : condition_lo;                                                    \
    output_dst            : log_header.log##LOG##_byte##BYTE;                                \
    output_value          : register_lo;                                                     \
}                                                                                            \
                                                                                             \
action read_update_log##LOG##_byte##BYTE () {                                                \
    read_update_log##LOG##_byte##BYTE##_alu.execute_stateful_alu(0);                         \
}                                                                                            \
                                                                                             \
table read_update_log##LOG##_byte##BYTE##_tab {                                              \
    actions {                                                                                \
        read_update_log##LOG##_byte##BYTE;                                                   \
    }                                                                                        \
    default_action : read_update_log##LOG##_byte##BYTE;                                      \
}

READ_UPDATE_LOG_BYTE(0, 0)
READ_UPDATE_LOG_BYTE(0, 4)
READ_UPDATE_LOG_BYTE(0, 8)
READ_UPDATE_LOG_BYTE(0, 12)
READ_UPDATE_LOG_BYTE(1, 0)
READ_UPDATE_LOG_BYTE(1, 4)
READ_UPDATE_LOG_BYTE(1, 8)
READ_UPDATE_LOG_BYTE(1, 12)
READ_UPDATE_LOG_BYTE(2, 0)
READ_UPDATE_LOG_BYTE(2, 4)
READ_UPDATE_LOG_BYTE(2, 8)
READ_UPDATE_LOG_BYTE(2, 12)
READ_UPDATE_LOG_BYTE(3, 0)
READ_UPDATE_LOG_BYTE(3, 4)
READ_UPDATE_LOG_BYTE(3, 8)
READ_UPDATE_LOG_BYTE(3, 12)
READ_UPDATE_LOG_BYTE(4, 0)
READ_UPDATE_LOG_BYTE(4, 4)
READ_UPDATE_LOG_BYTE(4, 8)
READ_UPDATE_LOG_BYTE(4, 12)
READ_UPDATE_LOG_BYTE(5, 0)
READ_UPDATE_LOG_BYTE(5, 4)
READ_UPDATE_LOG_BYTE(5, 8)
READ_UPDATE_LOG_BYTE(5, 12)
READ_UPDATE_LOG_BYTE(6, 0)
READ_UPDATE_LOG_BYTE(6, 4)
READ_UPDATE_LOG_BYTE(6, 8)
READ_UPDATE_LOG_BYTE(6, 12)
READ_UPDATE_LOG_BYTE(7, 0)
READ_UPDATE_LOG_BYTE(7, 4)
READ_UPDATE_LOG_BYTE(7, 8)
READ_UPDATE_LOG_BYTE(7, 12)

/*===============================================================================================*/
/* the counter for IPv4 identification field */

// register ipv4_id_counter {
//     width          : 16;
//     instance_count : 1;
// }
//
// blackbox stateful_alu read_update_ipv4_id_counter_alu {
//     reg : ipv4_id_counter;
//
//     update_lo_1_value     : register_lo + 1;
//
//     // output
//     output_dst            : md.ipv4_id;
//     output_value          : register_lo;
// }
//
// action read_update_ipv4_id_counter () {
//     read_update_ipv4_id_counter_alu.execute_stateful_alu(0);
// }
//
// table ipv4_id_counter_tab {
//     reads {
//         log_header              : valid;
//         ipv4.dstAddr            : exact;
//         eg_intr_md.egress_port  : exact;
//     }
//     actions {
//         read_update_ipv4_id_counter;
//         nop;
//     }
//     default_action : nop;
// }


/*===============================================================================================*/
/* Remove log header */

action remove_logHeader() {
    remove_header(log_header);
    modify_field(udp.dstPort, UDP_PORT_IB);
}
action correct_logHeader(macSrc, macDst, ipSrc, ipDst) {
    modify_field(ethernet.srcAddr, macSrc);
    modify_field(ethernet.dstAddr, macDst);
    modify_field(ipv4.srcAddr, ipSrc);
    modify_field(ipv4.dstAddr, ipDst);
    modify_field(ipv4.identification, 0);
    add_to_field(ipv4.totalLen, LOG_HEADER_LEN);
    add_to_field(udp.hdr_length, LOG_HEADER_LEN);
    // add_to_field(md.another_udp_len, LOG_HEADER_LEN);
}

table remove_logHeader_tab {
    reads {
        ipv4.dstAddr            : exact;
        eg_intr_md.egress_port  : exact;
    }
    actions {
        remove_logHeader;
        correct_logHeader;
        _drop;
    }
    default_action : _drop;
}

/*===============================================================================================*/
/* Checksum update especially for adding log header */

field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input        { ipv4_checksum_list; }
    algorithm    : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum {
    update ipv4_checksum;
}

// field_list udp_ipv4_checksum_list {
//     ipv4.srcAddr;
//     ipv4.dstAddr;
//     8'0; ipv4.protocol;
//     udp.srcPort;
//     udp.dstPort;
//     udp.hdr_length;
//     ib_bth.opCode;
//     ib_bth.se;
//     ib_bth.migReq;
//     ib_bth.padCnt;
//     ib_bth.tver;
//     ib_bth.p_key;
//     ib_bth.reserved;
//     ib_bth.dqpn;
//     ib_bth.ack_req;
//     ib_bth.reserved2;
//     ib_bth.psn;
//     ib_reth.virtAddr_h;
//     ib_reth.virtAddr_l;
//     ib_reth.rkey;
//     ib_reth.len;
//     log_header.log0_byte0;
//     log_header.log0_byte4;
//     log_header.log0_byte8;
//     log_header.log0_byte12;
//     log_header.log1_byte0;
//     log_header.log1_byte4;
//     log_header.log1_byte8;
//     log_header.log1_byte12;
//     log_header.log2_byte0;
//     log_header.log2_byte4;
//     log_header.log2_byte8;
//     log_header.log2_byte12;
//     log_header.log3_byte0;
//     log_header.log3_byte4;
//     log_header.log3_byte8;
//     log_header.log3_byte12;
//     log_header.log4_byte0;
//     log_header.log4_byte4;
//     log_header.log4_byte8;
//     log_header.log4_byte12;
//     log_header.log5_byte0;
//     log_header.log5_byte4;
//     log_header.log5_byte8;
//     log_header.log5_byte12;
//     log_header.log6_byte0;
//     log_header.log6_byte4;
//     log_header.log6_byte8;
//     log_header.log6_byte12;
//     log_header.log7_byte0;
//     log_header.log7_byte4;
//     log_header.log7_byte8;
//     log_header.log7_byte12;
//     payload;
// }
//
// field_list_calculation udp_ipv4_checksum {
//     input        { udp_ipv4_checksum_list; }
//     algorithm    : csum16;
//     output_width : 16;
// }
//
// calculated_field udp.checksum {
//     update udp_ipv4_checksum;
// }

/*===============================================================================================*/
/* Ingress */

control ingress {
    if (valid(ctrl)) {
        /* Stage 0 */
        apply(receive_ctrl);
    } else {
        /* Stage 0 */
        apply(ban_acl);
        if (valid(ib_reth)){
            /* Stage 1 */
            apply(split_tstamp_high32_tab); //obtain timestamp for this packet
            apply(cursor_tab);
            /* Stage 2 */
            apply(forward_reth);
            apply(add_logHeader_tab);
            apply(form_log_byte0_tab);
            apply(form_log_byte4_tab);
            apply(form_log_byte8_tab);
            apply(form_log_byte12_tab);

            /* Stage 3 - end */
            apply(read_update_log0_byte0_tab);
            apply(read_update_log0_byte4_tab);
            apply(read_update_log0_byte8_tab);
            apply(read_update_log0_byte12_tab);
            apply(read_update_log1_byte0_tab);
            apply(read_update_log1_byte4_tab);
            apply(read_update_log1_byte8_tab);
            apply(read_update_log1_byte12_tab);
            apply(read_update_log2_byte0_tab);
            apply(read_update_log2_byte4_tab);
            apply(read_update_log2_byte8_tab);
            apply(read_update_log2_byte12_tab);
            apply(read_update_log3_byte0_tab);
            apply(read_update_log3_byte4_tab);
            apply(read_update_log3_byte8_tab);
            apply(read_update_log3_byte12_tab);
            apply(read_update_log4_byte0_tab);
            apply(read_update_log4_byte4_tab);
            apply(read_update_log4_byte8_tab);
            apply(read_update_log4_byte12_tab);
            apply(read_update_log5_byte0_tab);
            apply(read_update_log5_byte4_tab);
            apply(read_update_log5_byte8_tab);
            apply(read_update_log5_byte12_tab);
            apply(read_update_log6_byte0_tab);
            apply(read_update_log6_byte4_tab);
            apply(read_update_log6_byte8_tab);
            apply(read_update_log6_byte12_tab);
            apply(read_update_log7_byte0_tab);
            apply(read_update_log7_byte4_tab);
            apply(read_update_log7_byte8_tab);
            apply(read_update_log7_byte12_tab);
        } else {
            apply(forward);
        }
    }
}

/*===============================================================================================*/
/* Egress */

control egress {
    if (valid(log_header)) {
        apply(remove_logHeader_tab);
    }
}

