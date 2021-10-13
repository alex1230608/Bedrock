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
        drop1:32;
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

register ts {
    width : 32;
    instance_count : NUM_WINDOWS;
}


action read_update_ts (winId) {
    register_read(md.tstamp_diff, ts, winId);
    register_write(ts, winId, md.tstamp);
    modify_field(meta.temp_tstamp, md.tstamp);
    subtract_from_field(meta.temp_tstamp, md.tstamp_diff);
    modify_field(md.tstamp_diff, meta.temp_tstamp);
    modify_field(md.winId, winId);
}

table last_time {
    reads {
        md.tstamp : ternary;
    }
    actions {
        read_update_ts;
    }
    size: NUM_WINDOWS;
}


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
}

action send_entry_digest() {
    modify_field(md.digest_type, 1);
    generate_digest(0, digest_fields);
}

table generate_entry_digest_tab {
    reads {
        md.tstamp_diff : ternary;  // need an entry matching on [WIN_TIME, 0xFFFFFFFF]
                                   // make default send, while matched case for nop:
                                   // if WIN_TIME = 0x10, diff & 0xFFFFFFF0 == 0 : nop
                                   //                                     default: send
    }
    actions {
        send_entry_digest;
        nop;
    }
    //default_action: send_entry_digest;
    size: 2;
}

/*===============================================================================================*/
/* Counter for flow size per window */

primitive_action hash_function0();
primitive_action hash_function1();
primitive_action hash_function2();
primitive_action hash_function3();

register cmin_win0_hash0{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win0_hash0() {
    hash_function0();
    register_read(md.cmin_win0_hash0, cmin_win0_hash0, meta.hash_calc);
    add_to_field(md.cmin_win0_hash0,ipv4.totalLen);
    register_write(cmin_win0_hash0, meta.hash_calc, md.cmin_win0_hash0);
}
table read_update_cmin_win0_hash0_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win0_hash0;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win1_hash0{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win1_hash0() {
    hash_function0();
    register_read(md.cmin_win1_hash0, cmin_win1_hash0, meta.hash_calc);
    add_to_field(md.cmin_win1_hash0,ipv4.totalLen);
    register_write(cmin_win1_hash0, meta.hash_calc, md.cmin_win1_hash0);
}
table read_update_cmin_win1_hash0_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win1_hash0;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win2_hash0{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win2_hash0() {
    hash_function0();
    register_read(md.cmin_win2_hash0, cmin_win2_hash0, meta.hash_calc);
    add_to_field(md.cmin_win2_hash0,ipv4.totalLen);
    register_write(cmin_win2_hash0, meta.hash_calc, md.cmin_win2_hash0);
}
table read_update_cmin_win2_hash0_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win2_hash0;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win3_hash0{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win3_hash0() {
    hash_function0();
    register_read(md.cmin_win3_hash0, cmin_win3_hash0, meta.hash_calc);
    add_to_field(md.cmin_win3_hash0,ipv4.totalLen);
    register_write(cmin_win3_hash0, meta.hash_calc, md.cmin_win3_hash0);
}
table read_update_cmin_win3_hash0_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win3_hash0;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win0_hash1{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win0_hash1() {
    hash_function1();
    register_read(md.cmin_win0_hash1, cmin_win0_hash1, meta.hash_calc);
    add_to_field(md.cmin_win0_hash1,ipv4.totalLen);
    register_write(cmin_win0_hash1, meta.hash_calc, md.cmin_win0_hash1);
}
table read_update_cmin_win0_hash1_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win0_hash1;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win1_hash1{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win1_hash1() {
    hash_function1();
    register_read(md.cmin_win1_hash1, cmin_win1_hash1, meta.hash_calc);
    add_to_field(md.cmin_win1_hash1,ipv4.totalLen);
    register_write(cmin_win1_hash1, meta.hash_calc, md.cmin_win1_hash1);
}
table read_update_cmin_win1_hash1_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win1_hash1;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win2_hash1{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win2_hash1() {
    hash_function1();
    register_read(md.cmin_win2_hash1, cmin_win2_hash1, meta.hash_calc);
    add_to_field(md.cmin_win2_hash1,ipv4.totalLen);
    register_write(cmin_win2_hash1, meta.hash_calc, md.cmin_win2_hash1);
}
table read_update_cmin_win2_hash1_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win2_hash1;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win3_hash1{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win3_hash1() {
    hash_function1();
    register_read(md.cmin_win3_hash1, cmin_win3_hash1, meta.hash_calc);
    add_to_field(md.cmin_win3_hash1,ipv4.totalLen);
    register_write(cmin_win3_hash1, meta.hash_calc, md.cmin_win3_hash1);
}
table read_update_cmin_win3_hash1_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win3_hash1;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win0_hash2{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win0_hash2() {
    hash_function2();
    register_read(md.cmin_win0_hash2, cmin_win0_hash2, meta.hash_calc);
    add_to_field(md.cmin_win0_hash2,ipv4.totalLen);
    register_write(cmin_win0_hash2, meta.hash_calc, md.cmin_win0_hash2);
}
table read_update_cmin_win0_hash2_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win0_hash2;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win1_hash2{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win1_hash2() {
    hash_function2();
    register_read(md.cmin_win1_hash2, cmin_win1_hash2, meta.hash_calc);
    add_to_field(md.cmin_win1_hash2,ipv4.totalLen);
    register_write(cmin_win1_hash2, meta.hash_calc, md.cmin_win1_hash2);
}
table read_update_cmin_win1_hash2_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win1_hash2;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win2_hash2{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win2_hash2() {
    hash_function2();
    register_read(md.cmin_win2_hash2, cmin_win2_hash2, meta.hash_calc);
    add_to_field(md.cmin_win2_hash2,ipv4.totalLen);
    register_write(cmin_win2_hash2, meta.hash_calc, md.cmin_win2_hash2);
}
table read_update_cmin_win2_hash2_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win2_hash2;
    }                                                                           
    size: 1;                                                                   
}
register cmin_win3_hash2{
    width: 32;                                                                                  
    instance_count: CMIN_SIZE;                                                                  
}
action read_update_cmin_win3_hash2() {
    hash_function2();
    register_read(md.cmin_win3_hash2, cmin_win3_hash2, meta.hash_calc);
    add_to_field(md.cmin_win3_hash2,ipv4.totalLen);
    register_write(cmin_win3_hash2, meta.hash_calc, md.cmin_win3_hash2);
}
table read_update_cmin_win3_hash2_tab {
    reads {                                                                            
        ib_bth   : valid;                                                             
        ipv4.dstAddr : exact;                                                        
        md.winId : exact;                                                           
    }                                                                              
    actions {     
         read_update_cmin_win3_hash2;
    }                                                                           
    size: 1;                                                                   
}


/*===============================================================================================*/
/* get min of the sketch*/

primitive_action comp1();
primitive_action comp2();

action comp_cmin_step1 () {
    comp1();
}

table comp_cmin_step1_tab {
    actions {
      comp_cmin_step1;
    }
    //default_action: comp_cmin_step1;
    size: 1;
}


action comp_cmin_step2 () {
     comp2();
}

table comp_cmin_step2_tab {
    actions {
      comp_cmin_step2;
    }
    //default_action: comp_cmin_step2;
    size: 1;
}

/*===============================================================================================*/
/* Split cmin value so that they can fit in range key constraint (20-bit) */
primitive_action split0();
primitive_action split1();
primitive_action split2();
primitive_action split3();

action split_cmin_win0_32_20_msb12 () {                                                         
    split0();                
}

action split_cmin_win1_32_20_msb12 () {                                                         
    split1();                
}

action split_cmin_win2_32_20_msb12 () {                                                         
    split2();                
}

action split_cmin_win3_32_20_msb12 () {                                                         
    split3();                
}

table split_cmin_win0_32_20_msb12_tab {                                                       
    actions{                                                                                    
        split_cmin_win0_32_20_msb12;                                                           
    }                                                                                           
    //default_action : split_cmin_win0_32_20_msb12;                                               
}

table split_cmin_win1_32_20_msb12_tab {                                                       
    actions{                                                                                    
        split_cmin_win1_32_20_msb12;                                                            
    }                                                                                           
    //default_action : split_cmin_win1_32_20_msb12;                                               
}

table split_cmin_win2_32_20_msb12_tab {                                                       
    actions{                                                                                    
        split_cmin_win2_32_20_msb12;                                                            
    }                                                                                           
    //default_action : split_cmin_win2_32_20_msb12;                                               
}

table split_cmin_win3_32_20_msb12_tab {                                                       
    actions{                                                                                    
        split_cmin_win3_32_20_msb12;                                                            
    }                                                                                           
    //default_action : split_cmin_win3_32_20_msb12;                                               
}
/*===============================================================================================*/

/* use winId to decide */
primitive_action win_id();

action match_win_id() {
    win_id();
}

table match_win_id_tab {
    actions{
        match_win_id;
    }
    //default_action : match_win_id();
}

/* Rate limit */

action send_ban_digest() {
    modify_field(md.digest_type, 2);
    generate_digest(0, digest_fields);
}

table rate_limit {
    reads {
        ib_bth             : valid;
        ipv4.dstAddr       : exact;
        meta.cmin_win : range;
        
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
        ib_bth       : valid;
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
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
    //exit();
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
    //default_action: nop;
    size : 1024;
}

/*===============================================================================================*/
/* Ingress */


control ingress {
    // Stage 0
    apply(get_user_id_tab);
	apply(forward);	
    
    apply(split_tstamp_high32_tab);

    // Stage 1
    
    apply(ban_acl);
    apply(last_time);
    
    // Stage 2
    
    apply(generate_entry_digest_tab);
    apply(read_update_cmin_win0_hash0_tab);
    apply(read_update_cmin_win1_hash0_tab);
    apply(read_update_cmin_win2_hash0_tab);
    apply(read_update_cmin_win3_hash0_tab);
    apply(read_update_cmin_win0_hash1_tab);
    apply(read_update_cmin_win1_hash1_tab);
    apply(read_update_cmin_win2_hash1_tab);
    apply(read_update_cmin_win3_hash1_tab);
    apply(read_update_cmin_win0_hash2_tab);
    apply(read_update_cmin_win1_hash2_tab);
    apply(read_update_cmin_win2_hash2_tab);
    apply(read_update_cmin_win3_hash2_tab);

    // Stage 3
    apply(comp_cmin_step1_tab);

    // Stage 4
    apply(comp_cmin_step2_tab);

    // Stage 5
    apply(split_cmin_win0_32_20_msb12_tab);
    apply(split_cmin_win1_32_20_msb12_tab);
    apply(split_cmin_win2_32_20_msb12_tab);
    apply(split_cmin_win3_32_20_msb12_tab);


    // Stage 6
    apply(match_win_id_tab);
    apply(rate_limit);
    apply(forward1);
    
    
}