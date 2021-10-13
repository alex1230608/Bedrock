/*
 * Copyright (C) 2017, ACANETS LAB, University of Massachusetts Lowell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

#include "headers.p4"
#include "parser.p4"

#define NUM_WINDOWS 4
#define WIN_TIME 0x4000   // ~ 1 sec (not used in p4, but in setup => for document)
#define CMIN_SIZE 0x10000
#define GRP_BROADCAST 666
#define CURSOR_WIDTH 8    // 8 < 2^8
#define LOG_SIZE_MINUS1 7 // 8 logs per packet
#define LOG_HEADER_LEN 128

// Following consts are for document and not used in the program
#define RECORD_SIZE 16  // 16-byte log
//#define ETHER_ADDR_LOG 0x506b4b42d824
//#define IP_ADDR_LOG 0x0a000802
//#define ETHER_ADDR_LOG 0x506b4b4ba8a2
//#define IP_ADDR_LOG 0x0a000805
#define ETHER_ADDR_LOG 0xd8c497724aed
#define IP_ADDR_LOG 0x0a000806

header_type intrinsic_metadata_t {
    fields {
        ingress_global_timestamp : 64;
        current_global_timestamp: 64;
    }
}

metadata intrinsic_metadata_t intrinsic_metadata;

header_type meta_t {
    fields {
        validate: 32;
        icrc_reth_payload_len0: 32;
        icrc_reth_payload_len4: 32;
        icrc_payload_len16: 32;
    }
}

metadata meta_t meta;

/*
parser start {
    //set_metadata(meta.ingress_time, intrinsic_metadata.ingress_global_timestamp);
    return ingress;
}
*/

action set_mc(grp) {
    modify_field(standard_metadata.egress_spec, grp);
}

action set_egr(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
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
        set_egr; 
        set_mc;
        nop;
    }
    //default_action : set_mc(GRP_BROADCAST);
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

primitive_action tstamp();

action split_tstamp_high32 () {
    tstamp();
    //modify_field_with_hash_based_offset(md.tstamp, 0, intrinsic_metadata.ingress_global_timestamp, 0x100000000);
}


table split_tstamp_high32_tab {
    actions{
        split_tstamp_high32;
    }
    //default_action : split_tstamp_high32;
    size : 1;
}

primitive_action tstamp1();

action split_tstamp1_high32 () {
    tstamp1();
    //modify_field_with_hash_based_offset(md.tstamp, 0, intrinsic_metadata.ingress_global_timestamp, 0x100000000);
}


table split_tstamp1_high32_tab {
    actions{
        split_tstamp1_high32;
    }
    //default_action : split_tstamp_high32;
    size : 1;
}

/*===============================================================================================*/
/* Check ingress port and source IP */

action drop_exit() {
    drop();
    //exit();
}

table check_ingress_ip {
    reads {
        ipv4.srcAddr            : exact;
        standard_metadata.ingress_port : exact;
    }
    actions {
        nop;
        drop_exit;
    }
    // default_action: _drop;
    size : 1024;
}

/*===============================================================================================*/
/* Decode the fake dqpn from client to real dqpn */

action change_to_real_dqpn(real_dqpn) {
    bit_xor(md.diff, ib_bth.dqpn, real_dqpn);
    modify_field(ib_bth.dqpn, real_dqpn);
}

table decode_dqpn {
    reads {
        ipv4.srcAddr  : exact;
        ipv4.dstAddr  : exact;
        ib_bth.dqpn   : exact;
    }
    actions {
        nop;
        drop_exit;
        change_to_real_dqpn;
    }
    // default_action : drop_exit;
    size : 32768;
}

/*===============================================================================================*/

table get_diff_each_byte_tab {
    actions {
        get_diff_each_byte;
    }
    //default_action : get_diff_each_byte;
}

primitive_action diff();
action get_diff_each_byte() {
    diff();
    //modify_field_with_shift(md.diff0, md.diff, 16, 0xFF);
    //modify_field_with_shift(md.diff1, md.diff, 8, 0xFF);
    //modify_field_with_shift(md.diff2, md.diff, 0, 0xFF);
}

/*===============================================================================================*/

#define POSSIBLE_LEN 512
#define POSSIBLE_LEN_P1 513
#define CRC_LOOKUP_SIZE_PER_BYTE 131073 // (256*POSSIBLE_LEN) + 1

/*===============================================================================================*/
/* Receive auth control message */

field_list digest_fields {
    md.digest_type;

    authCtrl.sip;
    authCtrl.fake_dqpn;
    authCtrl.real_dqpn;
    ipv4.srcAddr;
}

action send_entry_digest() {
    modify_field(md.digest_type, 3);
    generate_digest(0, digest_fields);
    drop();
}

table receive_authCtrl{
    reads {
        authCtrl : valid;
    }
    actions {
        nop;
        send_entry_digest;
    }
    //default_action : nop;
    size : 2;
}

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
    //default_action : _drop;
    size : 32000;
}


field_list icrc_payload_list {
   // masked lrh
   md.ones_32;
   md.ones_32;
   // ipv4 (ttl, checksum, tos masked)
   ipv4.version;
   ipv4.ihl;
   md.ones_8;
   ipv4.totalLen;
   ipv4.identification;
   ipv4.flags;
   ipv4.fragOffset;
   md.ones_8;
   ipv4.protocol;
   md.ones_16;
   ipv4.srcAddr;
   ipv4.dstAddr;
   // udp (checksum masked)
   udp.srcPort;
   udp.dstPort;
   udp.hdr_length;
   md.ones_16;
   // ib_bth (reserved masked)
   ib_bth.opCode;
   ib_bth.se;
   ib_bth.migReq;
   ib_bth.padCnt;
   ib_bth.tver;
   ib_bth.p_key;
   md.ones_8;
   ib_bth.dqpn;
   ib_bth.ack_req;
   ib_bth.reserved2;
   ib_bth.psn;
   // payload
   payload;
}

field_list_calculation icrc_payload {
   input        {icrc_payload_list;}

   algorithm    : crc32;
   output_width : 32;
}



primitive_action set_trailer();
primitive_action crc();

action get_icrc_action() {
   
   //modify_field(md.icrc_tmp4, icrc_reth_payload_len4);
   //modify_field_with_hash_based_offset(md.icrc_tmp4, 0, icrc_payload, 0x1000000);
   //modify_field(md.icrc_tmp4, tmp_crc.icrc_reth_payload_len4);
   //set_trailer();
   //crc();
   //set_trailer();
   
}


table get_icrc {
   reads {
      ib_bth          : valid;
   }
   actions {
      nop;
      get_icrc_action;
   }
   //default_action : nop();
   size : 2;
}


action remove_tmp_crc() {
   remove_header(tmp_crc);
}

table remove_tmp_crc_tab {
     reads {
         tmp_crc : valid;
     }
     actions {
         remove_tmp_crc;
         nop;
     }
     //default_action: nop;
     size : 2;
}

/*===============================================================================================*/
/* Ingress */


control ingress {
    // Stage 0    
  if(valid(authCtrl)) {
     apply(receive_authCtrl);
  } else {
     if (valid(ib_bth)) {
          apply(check_ingress_ip);
          apply(decode_dqpn);
          apply(get_diff_each_byte_tab);
          //apply(get_icrc_reth_payload_len0);
          //apply(get_icrc_reth_payload_len4);
          //apply(get_icrc_payload_len16);
          apply(get_icrc);
          apply(rdma_acl);
     }
     
	 apply(forward);
  }
    
}

/*===============================================================================================*/
/* Egress */

control egress {
    apply(acl);
    //if (valid(tmp_crc)){
        //apply(remove_tmp_crc_tab);
    //}
}

         