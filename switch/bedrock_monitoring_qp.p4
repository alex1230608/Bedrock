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

#include "includes/headers.p4"
#include "includes/parser.p4"
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>

#define NUM_WINDOWS 1
#define WIN_TIME 0xFFFFFFFF   // should never reset (not used in p4, but in setup => for document)
#define CMIN_SIZE 0x10000
// #define RATE_LIMIT_MASK 0xC0000000 // < 1GB/sec (not used in p4, but in setup => for document)
// use range of first 12 bits => range of MB

/*===============================================================================================*/
/* Basic port-to-port forwarding */

#define GRP_BROADCAST 666

action set_mc(grp) {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, grp);
}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action nop() {
}

action _drop() {
    drop();
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

// table acl {
//     reads {
//         ethernet.dstAddr : ternary;
//         ethernet.srcAddr : ternary;
//     }
//     actions {
//         nop;
//         _drop;
//     }
// }

// /*===============================================================================================*/
// /* obtain timestamps */
//
// // Use high 32-bit tstamp of the full 48 bits
// field_list tstamp {
//     _ingress_global_tstamp_;
// }
//
// field_list_calculation tstamp_high32 {
//     input {
//         tstamp;
//     }
//     algorithm : identity_msb;
//     output_width : 32;
// }
//
// action split_tstamp_high32 () {
//     modify_field_with_hash_based_offset(md.tstamp, 0, tstamp_high32, 0x100000000);
// }
//
// table split_tstamp_high32_tab {
//     actions{
//         split_tstamp_high32;
//     }
//     default_action : split_tstamp_high32;
//     size : 1;
// }

// /*===============================================================================================*/
// /* the per-window last_time timestamp */
//
// // timestamps
// register ts {
//     width : 32;
//     instance_count : NUM_WINDOWS;
// }
//
// // read and update the conn timestamp: low32
// blackbox stateful_alu read_update_ts_alu {
//     reg : ts;
//
//     update_lo_1_value     : md.tstamp;
//     update_hi_1_value     : md.tstamp - register_lo;
//
//     // output
//     output_dst            : md.tstamp_diff;
//     output_value          : alu_hi;
// }
//
// action read_update_ts (winId) {
//     read_update_ts_alu.execute_stateful_alu(winId);
//     modify_field(md.winId, winId);
// }
//
// table last_time {
//     reads {
//         md.tstamp : ternary;
//     }
//     actions {
//         read_update_ts;
//     }
//     size: NUM_WINDOWS;
// }

/*===============================================================================================*/
/* The digest table for sending to control plane */

field_list digest_fields {
    md.digest_type;

    md.winId;
    md.tstamp_diff;

    md.user_id;
    ib_bth.dqpn;
    ipv4.dstAddr;
    md.cmin_win0;
    md.cmin_win1;
    md.cmin_win2;
    md.cmin_win3;
    md.cmin_win0_32_20;
    md.cmin_win1_32_20;
    md.cmin_win2_32_20;
    md.cmin_win3_32_20;
    md.cmin_win0_20_0;
}

// action send_entry_digest() {
//     modify_field(md.digest_type, 1);
//     generate_digest(0, digest_fields);
// }
//
// table generate_entry_digest_tab {
//     reads {
//         md.tstamp_diff : ternary;  // need an entry matching on [WIN_TIME, 0xFFFFFFFF]
//                                    // make default send, while matched case for nop:
//                                    // if WIN_TIME = 0x10, diff & 0xFFFFFFF0 == 0 : nop
//                                    //                                     default: send
//     }
//     actions {
//         send_entry_digest;
//         nop;
//     }
//     default_action: send_entry_digest;
//     size: 2;
// }

/*===============================================================================================*/
/* Counter for flow size per window */

field_list cmin_hash_fields {
    md.user_id;
}

field_list_calculation cmin_hash0_calc {
    input {cmin_hash_fields;}
    algorithm : crc_16;
    output_width: 16;
}
field_list_calculation cmin_hash1_calc {
    input {cmin_hash_fields;}
    algorithm : crc_16_usb;
    output_width: 16;
}
field_list_calculation cmin_hash2_calc {
    input {cmin_hash_fields;}
    algorithm : crc_16_dnp;
    output_width: 16;
}
field_list_calculation cmin_hash3_calc {
    input {cmin_hash_fields;}
    algorithm : crc_16_dect;
    output_width: 16;
}

#define READ_UPDATE_CMIN(WIN, HASH)                                                             \
register cmin_win##WIN##_hash##HASH {                                                           \
    width: 32;                                                                                  \
    instance_count: CMIN_SIZE;                                                                  \
}                                                                                               \
                                                                                                \
blackbox stateful_alu read_update_cmin_win##WIN##_hash##HASH##_alu {                            \
    reg : cmin_win##WIN##_hash##HASH;                                                           \
                                                                                                \
    update_lo_1_value: register_lo + 1;                                                         \
                                                                                                \
    output_dst: md.cmin_win##WIN##_hash##HASH;                                                  \
    output_value: alu_lo;                                                                       \
}                                                                                               \
                                                                                                \
action read_update_cmin_win##WIN##_hash##HASH() {                                               \
    read_update_cmin_win##WIN##_hash##HASH##_alu.execute_stateful_alu_from_hash(cmin_hash##HASH##_calc);  \
}                                                                                               \
table read_update_cmin_win##WIN##_hash##HASH##_tab {                                            \
    reads {                                                                                     \
        ib_mad         : valid;                                                                 \
        ib_mad.attr_id : exact;                                                                 \
        ipv4.dstAddr   : exact;                                                                 \
    }                                                                                           \
    actions {                                                                                   \
        read_update_cmin_win##WIN##_hash##HASH;                                                 \
    }                                                                                           \
    size: 1;                                                                                    \
}

READ_UPDATE_CMIN(0, 0)
READ_UPDATE_CMIN(0, 1)
READ_UPDATE_CMIN(0, 2)
READ_UPDATE_CMIN(0, 3)

/*===============================================================================================*/
/* get min of the sketch*/

action comp_cmin_step1 () {
    min(md.cmin_win0_s1, md.cmin_win0_hash0, md.cmin_win0_hash1);
    min(md.cmin_win0_s2, md.cmin_win0_hash2, 0xFFFFFFFF);
}

table comp_cmin_step1_tab {
    actions {
      comp_cmin_step1;
    }
    default_action: comp_cmin_step1;
    size: 1;
}


action comp_cmin_step2 () {
    min(md.cmin_win0, md.cmin_win0_s1, md.cmin_win0_s2);
}

table comp_cmin_step2_tab {
    actions {
      comp_cmin_step2;
    }
    default_action: comp_cmin_step2;
    size: 1;
}

/*===============================================================================================*/
/* Split cmin value so that they can fit in range key constraint (20-bit) */

#define SPLIT_FIELD(SRCHEADER, SRCFIELD, NAME, POS, WIDTH, WIDTHMASK)                           \
table split_##NAME##_##POS##WIDTH##_tab {                                                       \
    actions{                                                                                    \
        split_##NAME##_##POS##WIDTH;                                                            \
    }                                                                                           \
    default_action : split_##NAME##_##POS##WIDTH;                                               \
}                                                                                               \
                                                                                                \
field_list NAME##_list {                                                                        \
    SRCHEADER.SRCFIELD;                                                                         \
}                                                                                               \
                                                                                                \
field_list_calculation NAME##_##POS##WIDTH {                                                    \
    input {                                                                                     \
        NAME##_list;                                                                            \
    }                                                                                           \
    algorithm : identity_##POS;                                                                 \
    output_width : WIDTH;                                                                       \
}                                                                                               \
                                                                                                \
action split_##NAME##_##POS##WIDTH () {                                                         \
    modify_field_with_hash_based_offset(md.NAME, 0, NAME##_##POS##WIDTH, WIDTHMASK);            \
}

SPLIT_FIELD(md, cmin_win0, cmin_win0_20_0, lsb, 20, 0x100000)

/*===============================================================================================*/
/* Rate limit */

action send_ban_digest() {
    modify_field(md.digest_type, 2);
    generate_digest(0, digest_fields);
}

table rate_limit {
    reads {
        ib_mad            : valid;
        ib_mad.attr_id    : exact;
        ipv4.dstAddr      : exact;
        md.cmin_win0_20_0 : range;
    }
    actions {
        send_ban_digest;
        nop;
    }
    default_action : nop;
    size : 1024;
}

/*===============================================================================================*/
/* Get User id */

table get_user_id_tab {
    reads {
        ib_mad         : valid;
        ib_mad.attr_id : exact;
        ipv4.srcAddr   : exact;
        ipv4.dstAddr   : exact;
    }
    actions {
        nop;
        get_user_id;
    }
    default_action : nop;
    size : 1024;
}

action get_user_id(user_id) {
    modify_field(md.user_id, user_id);
}

/*===============================================================================================*/
/* Banning ACL */

action drop_exit() {
    drop();
    exit();
}

table ban_acl {
    reads {
        // ib_bth       : valid;
        // ipv4.dstAddr : exact;
        // ib_bth.dqpn  : exact;
        md.user_id : exact;
    }
    actions {
        drop_exit;
        nop;
    }
    default_action: nop;
    size : 1024;
}

/*===============================================================================================*/
/* Ingress */

control ingress {
    /* Stage 0 */
    apply(get_user_id_tab);
    apply(forward);
    // apply(split_tstamp_high32_tab); //obtain timestamp for this packet

    /* Stage 1 */
    apply(ban_acl);
    // apply(last_time);

    /* Stage 1 */
    apply(read_update_cmin_win0_hash0_tab);
    apply(read_update_cmin_win0_hash1_tab);
    apply(read_update_cmin_win0_hash2_tab);
    // apply(read_update_cmin_win0_hash3_tab);

    /* Stage 2 */
    apply(comp_cmin_step1_tab);

    /* Stage 3 */
    apply(comp_cmin_step2_tab);

    /* Stage 4 */
    apply(split_cmin_win0_20_0_lsb20_tab);

    /* Stage 5 */
    apply(rate_limit);
}

/*===============================================================================================*/
/* Egress */

control egress {
    // apply(acl);
}

