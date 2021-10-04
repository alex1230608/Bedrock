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

table acl {
    reads {
        ethernet.dstAddr : ternary;
        ethernet.srcAddr : ternary;
    }
    actions {
        nop;
        _drop;
    }
    size : 1024;
}

/*===============================================================================================*/
/* Calculate end virtual address */

action copy_len() {
    // subtract(md.rdma_len, ib_reth.len, md.one_48);  // somehow, compile fail if using subtract
    // add (md.rdma_len, ib_reth.len, 0xFFFFFFFF);
    modify_field (md.rdma_len, ib_reth.len);
}

@pragma stage 0
table to_48bit_rdma_len {
    actions {
        copy_len;
    }
    default_action : copy_len;
    size : 1;
}

action cal_rdma_end_action() {
    add(md.rdma_end_l, ib_reth.virtAddr_l, md.rdma_len);
}

@pragma stage 1
table cal_rdma_end {
   actions {
       cal_rdma_end_action;
   }
   default_action : cal_rdma_end_action;
   size : 1;
}

/*===============================================================================================*/
/* Cut 48-bit address into 16-bit chunks */

#define SPLIT_FIELD(SRCHEADER, SRCFIELD, NAME, POS, WIDTH, WIDTHMASK)                           \
table split_##NAME##_##POS##WIDTH##_tab {                                                       \
    actions{                                                                                    \
        split_##NAME##_##POS##WIDTH;                                                            \
    }                                                                                           \
    default_action : split_##NAME##_##POS##WIDTH;                                               \
    size : 1;                                                                                   \
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

@pragma stage 0
SPLIT_FIELD(ib_reth, virtAddr_l, startAddr_20_0,  lsb, 20, 0x100000)
@pragma stage 0
SPLIT_FIELD(ib_reth, virtAddr_l, startAddr_32_0,  lsb, 32, 0x100000000)
@pragma stage 0
SPLIT_FIELD(ib_reth, virtAddr_l, startAddr_48_20, msb, 28, 0x10000000)
@pragma stage 1
SPLIT_FIELD(md, startAddr_48_20, startAddr_48_32, msb, 16, 0x10000)
@pragma stage 1
SPLIT_FIELD(md, startAddr_32_0,  startAddr_32_12, msb, 20, 0x100000)
@pragma stage 1
SPLIT_FIELD(md, startAddr_20_0,  startAddr_20_12, msb, 8,  0x100)

@pragma stage 2
SPLIT_FIELD(md, rdma_end_l,    endAddr_20_0,  lsb, 20, 0x100000)
@pragma stage 2
SPLIT_FIELD(md, rdma_end_l,    endAddr_32_0,  lsb, 32, 0x100000000)
@pragma stage 2
SPLIT_FIELD(md, rdma_end_l,    endAddr_48_20, msb, 28, 0x10000000)
@pragma stage 3
SPLIT_FIELD(md, endAddr_48_20, endAddr_48_32, msb, 16, 0x10000)
@pragma stage 3
SPLIT_FIELD(md, endAddr_32_0,  endAddr_32_12, msb, 20, 0x100000)
@pragma stage 3
SPLIT_FIELD(md, endAddr_20_0,  endAddr_20_12, msb, 8,  0x100)

/*===============================================================================================*/
/* Diff tables for Start and End addresses */

#define LARGE_ADDR_TO_GRP_MASK(SIDE)                                                            \
table SIDE##_large_addr_to_grpId_objMask {                                                      \
    reads {                                                                                     \
        ib_bth.dqpn         : exact;                                                            \
        md.SIDE##Addr_48_32 : range;                                                            \
    }                                                                                           \
    actions {                                                                                   \
        nop;                                                                                    \
        set_##SIDE##_grpId_objMask;                                                             \
    }                                                                                           \
    default_action : nop;                                                                       \
    size : 2450;                                                                                 \
}

#define MEDIUM_ADDR_TO_GRP_MASK(SIDE)                                                           \
table SIDE##_medium_addr_to_grpId_objMask {                                                     \
    reads {                                                                                     \
        ib_bth.dqpn         : exact;                                                            \
        md.SIDE##Addr_48_32 : exact;                                                            \
        md.SIDE##Addr_32_12 : range;                                                            \
    }                                                                                           \
    actions {                                                                                   \
        nop;                                                                                    \
        set_##SIDE##_grpId_objMask;                                                             \
    }                                                                                           \
    default_action : nop;                                                                       \
    size : 4400;                                                                                 \
}

#define SMALL_ADDR_TO_GRP_MASK(SIDE)                                                            \
table SIDE##_small_addr_to_grpId_objMask {                                                      \
    reads {                                                                                     \
        ib_bth.dqpn         : exact;                                                            \
        md.SIDE##Addr_48_20 : exact;                                                            \
        md.SIDE##Addr_20_12 : range;                                                            \
    }                                                                                           \
    actions {                                                                                   \
        nop;                                                                                    \
        set_##SIDE##_grpId_objMask;                                                             \
    }                                                                                           \
    default_action : nop;                                                                       \
    size : 4050;                                                                                \
}

#define SINGLE_ADDR_TO_GRP_MASK(SIDE)                                                           \
table SIDE##_singlePage_addr_to_grpId_objMask {                                                 \
    reads {                                                                                     \
        ib_bth.dqpn         : exact;                                                            \
        md.SIDE##Addr_48_20 : exact;                                                            \
        md.SIDE##Addr_20_12 : exact;                                                            \
    }                                                                                           \
    actions {                                                                                   \
        nop;                                                                                    \
        set_##SIDE##_grpId_objMask;                                                             \
    }                                                                                           \
    default_action : nop;                                                                       \
    size : 32000;                                                                                \
}                                                                                               \
                                                                                                \
action set_##SIDE##_grpId_objMask(SIDE##_priority1, SIDE##_priority2, SIDE##_priority3) {       \
    modify_field(md.SIDE##_priority1, SIDE##_priority1);                                        \
    modify_field(md.SIDE##_priority2, SIDE##_priority2);                                        \
    modify_field(md.SIDE##_priority3, SIDE##_priority3);                                        \
}




// @pragma entries_with_ranges 850
LARGE_ADDR_TO_GRP_MASK(start)
// @pragma entries_with_ranges 850
LARGE_ADDR_TO_GRP_MASK(end)
// @pragma entries_with_ranges 750
MEDIUM_ADDR_TO_GRP_MASK(start)
// @pragma entries_with_ranges 750
MEDIUM_ADDR_TO_GRP_MASK(end)
// @pragma entries_with_ranges 2000
SMALL_ADDR_TO_GRP_MASK(start)
// @pragma entries_with_ranges 2000
SMALL_ADDR_TO_GRP_MASK(end)
@pragma ignore_table_dependency start_small_addr_to_grpId_objMask
SINGLE_ADDR_TO_GRP_MASK(start)
@pragma ignore_table_dependency end_small_addr_to_grpId_objMask
SINGLE_ADDR_TO_GRP_MASK(end)


// /*===============================================================================================*/
// /* join the object mask */
//
// action join_masks() {
//     bit_and(md.join_objMask, md.start_objMask, md.end_objMask);
// }
//
// table join_masks_tab {
//     actions {
//         join_masks;
//     }
//     default_action : join_masks;
//     size : 1;
// }

// /*===============================================================================================*/
// /* Get ACL object for both start and end */
//
// #define GET_ACL_OBJ(SIDE)                                                                       \
// action set_##SIDE##_objId(objId) {                                                              \
//     modify_field(md.SIDE##_objId, objId);                                                       \
// }                                                                                               \
//                                                                                                 \
// table get_##SIDE##_objId {                                                                      \
//     reads {                                                                                     \
//         md.SIDE##_grpId : exact;                                                                \
//         md.join_objMask : exact;                                                                \
//     }                                                                                           \
//     actions {                                                                                   \
//         nop;                                                                                    \
//         set_##SIDE##_objId;                                                                     \
//     }                                                                                           \
//     default_action : nop;                                                                       \
//     size : 28000;                                                                               \
// }
//
// GET_ACL_OBJ(start)
// GET_ACL_OBJ(end)

/*===============================================================================================*/
/* Set obj id based on priority P */

#define SET_OBJ_ID(P)                                                                           \
table set_objId##P##_tab {                                                                      \
    actions {                                                                                   \
        set_objId##P;                                                                           \
    }                                                                                           \
    default_action : set_objId##P;                                                              \
}                                                                                               \
                                                                                                \
action set_objId##P() {                                                                         \
    modify_field(md.objId, md.start_priority##P);                                               \
}

// @pragma stage 10
SET_OBJ_ID(1)
// @pragma stage 10
SET_OBJ_ID(2)
// @pragma stage 10
SET_OBJ_ID(3)

/*===============================================================================================*/
/* ACL table based on objId */

table rdma_acl {
    reads {
        md.objId : exact;
        ib_bth.opCode  : exact;
    }
    actions {
        nop;
        _drop;
    }
    default_action : _drop;
    size : 32000;
}

/*===============================================================================================*/
/* Ingress */

control ingress {
    /* Stage 0 */
    apply(forward);

    if (valid(ib_reth)) {
        /* Stage 0 */
        apply(to_48bit_rdma_len);
        apply(split_startAddr_20_0_lsb20_tab);
        apply(split_startAddr_32_0_lsb32_tab);
        apply(split_startAddr_48_20_msb28_tab);

        /* Stage 1 */
        apply(split_startAddr_48_32_msb16_tab);
        apply(split_startAddr_32_12_msb20_tab);
        apply(split_startAddr_20_12_msb8_tab);
        apply(cal_rdma_end);

        /* Stage 2 */
        apply(start_large_addr_to_grpId_objMask);
        apply(split_endAddr_20_0_lsb20_tab);
        apply(split_endAddr_32_0_lsb32_tab);
        apply(split_endAddr_48_20_msb28_tab);

        /* Stage 3 */
        apply(split_endAddr_48_32_msb16_tab);
        apply(split_endAddr_32_12_msb20_tab);
        apply(split_endAddr_20_12_msb8_tab);

        /* Stage 3-4 */
        apply(start_medium_addr_to_grpId_objMask);

        /* Stage 5 */
        apply(start_small_addr_to_grpId_objMask);
        apply(start_singlePage_addr_to_grpId_objMask);

        /* Stage 6-9 */
        apply(end_large_addr_to_grpId_objMask);
        apply(end_medium_addr_to_grpId_objMask);
        apply(end_small_addr_to_grpId_objMask);
        apply(end_singlePage_addr_to_grpId_objMask);

        // /* Stage 8 */
        // apply(join_masks_tab);

        // /* Stage 9 */
        // apply(get_start_objId);
        // apply(get_end_objId);

        // if (md.start_objId == md.end_objId) {
        //     /* Stage 10 */
        //     apply(rdma_acl);
        // }

        // start_priorityP will be 0 if None, and end_priorityP will be 1 if None,
        // and all objId will be > 1, so equality also checks existence
        if (md.start_priority1 == md.end_priority1) {
            apply(set_objId1_tab);
        } else if (md.start_priority2 == md.end_priority2) {
            apply(set_objId2_tab);
        } else if (md.start_priority3 == md.end_priority3) {
            apply(set_objId3_tab);
        }
        apply(rdma_acl);

    }
}

/*===============================================================================================*/
/* Egress */

control egress {
    apply(acl);
}

