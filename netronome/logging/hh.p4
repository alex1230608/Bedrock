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
        hash_calc: 16;
        temp_tstamp:16;
        cmin_win:32;
        cursor:8;
        validate: 32;
        drop1: 32;
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

table forward_reth {
    reads {
        md.cursor               : ternary;
        ipv4.dstAddr            : exact;
    }
    actions {
        set_egr; 
        set_mc;
        nop;
    }

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
/* Receive control message (so far for logging server's side channel attack alarm) */

field_list digest_fields {
    md.digest_type;

    ctrl.banned_dqpn;
    ipv4.dstAddr;
}
primitive_action shut();

action send_entry_digest() {
    modify_field(md.digest_type, 2);
    generate_digest(0, digest_fields);
    shut();
    modify_field(meta.drop1, 1);
    //drop();
    
    //exit();
}

table receive_ctrl{
    actions {
        send_entry_digest;
    }
    //default_action : send_entry_digest;
}

/*===============================================================================================*/
/* the cursor for next request log */

register cursor {
    width          : CURSOR_WIDTH;
    instance_count : 1;
}

primitive_action cursor_update();

action read_update_cursor () {
    register_read(meta.cursor, cursor, 0);
    cursor_update();
    modify_field(md.cursor, meta.cursor);
    register_write(cursor, 0, meta.cursor);
}

table cursor_tab {
    reads {
        ib_reth : valid;
    }
    actions {
        read_update_cursor;
        nop;
    }
    //default_action : nop;
    size: 1;
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

/*===============================================================================================*/
/* Form log */
primitive_action form_log();                                                                                             
                                                                                                
action form_log_byte() {                                                                  
    form_log();    
}                                                                                               
                                                                                                
table form_log_byte_tab {                                                               
    actions{                                                                                    
        form_log_byte;                                                                    
    }                                                                                           
    //default_action : form_log_byte;                                                       
}

/*===============================================================================================*/
/* Read and/or update logs */
/* Read the batch of log if cursor == 0 */
/* Update one log */

primitive_action log_byte();
action read_update_log_byte () {  
    log_byte();                               
    //read_update_log_byte_alu.execute_stateful_alu(0);                         
}                                                                                            
                                                                                             
table read_update_log_byte_tab {                                              
    actions {                                                                                
        read_update_log_byte;                                                   
    }                                                                                        
    //default_action : read_update_log_byte;                                      
}

/*===============================================================================================*/
/* Remove log header */
primitive_action corrects();

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
    corrects();
    // add_to_field(md.another_udp_len, LOG_HEADER_LEN);
}

table remove_logHeader_tab {
    reads {
        ipv4.dstAddr            : exact;
        standard_metadata.egress_port  : exact;
    }
    actions {
        remove_logHeader;
        correct_logHeader;
        _drop;
    }
    //default_action : _drop;
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

primitive_action banned();

action ban() {
    banned();
}

table ban_acl {
    actions {
        ban;
    }
    //default_action: nop;
    size : 2;
}

table forward1 {
    reads {
        meta.drop1           : exact;
    }
    actions {
        set_egr; 
        set_mc;
        nop;
    }
    //default_action : set_mc(GRP_BROADCAST);
}
/*===============================================================================================*/
/* Ingress */


control ingress {
    // Stage 0    
  if (valid(ctrl)) {
        /* Stage 0 */
        //apply(split_tstamp_high32_tab);
     apply(receive_ctrl);
  } else {
	 apply(ban_acl);
     if (valid(ib_reth)) {
         apply(split_tstamp_high32_tab); //obtain timestamp for this packet
         apply(cursor_tab);
         apply(forward_reth);
         apply(add_logHeader_tab);
         apply(form_log_byte_tab);
         apply(read_update_log_byte_tab);
         apply(rdma_acl);

     } else {
         apply(forward);
         apply(split_tstamp1_high32_tab);
     }
  }
  apply(forward1);
    
}

control egress {
    if (valid(log_header)) {
        apply(remove_logHeader_tab);
    }
}


         