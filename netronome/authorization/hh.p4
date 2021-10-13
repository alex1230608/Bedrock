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

/*===============================================================================================*/
/* Calculate end virtual address */

action copy_len() {
    // subtract(md.rdma_len, ib_reth.len, md.one_48);  // somehow, compile fail if using subtract
    // add (md.rdma_len, ib_reth.len, 0xFFFFFFFF);
    modify_field (md.rdma_len, ib_reth.len);
}


table to_48bit_rdma_len {
    actions {
        copy_len;
    }
    //default_action : copy_len;
    size : 1;
}

action cal_rdma_end_action() {
    add(md.rdma_end_l, ib_reth.virtAddr_l, md.rdma_len);
}

table cal_rdma_end {
   actions {
       cal_rdma_end_action;
   }
   //default_action : cal_rdma_end_action;
   size : 1;
}

/*===============================================================================================*/
/* Cut 48-bit address into 16-bit chunks */
primitive_action split_start();

action split_startAddr() {
    split_start();
}

table split_startAddr_tab {
    actions {
        split_startAddr;
    }
    //default_action : copy_len;
    size : 1;
}

primitive_action split_end();

action split_endAddr() {
    split_end();
}

table split_endAddr_tab {
    actions {
        split_endAddr;
    }
    //default_action : copy_len;
    size : 1;
}

/*===============================================================================================*/
/* Diff tables for Start and End addresses */

action set_start_grpId_objMask(start_priority1, start_priority2, start_priority3) {       
    modify_field(md.start_priority1, start_priority1);                                        
    modify_field(md.start_priority2, start_priority2);                                        
    modify_field(md.start_priority3, start_priority3);                                        
}

action set_end_grpId_objMask(end_priority1, end_priority2, end_priority3) {       
    modify_field(md.end_priority1, end_priority1);                                        
    modify_field(md.end_priority2, end_priority2);                                        
    modify_field(md.end_priority3, end_priority3);                                        
}

table start_large_addr_to_grpId_objMask {                                                      
    reads {                                                                                     
        ib_bth.dqpn         : exact;                                                            
        md.startAddr_48_32 : range;                                                            
    }                                                                                           
    actions {                                                                                   
        nop;                                                                                    
        set_start_grpId_objMask;                                                             
    }                                                                                           
    //default_action : nop;                                                                       
    size : 2450;                                                                                 
}

table start_medium_addr_to_grpId_objMask {                                                     
    reads {                                                                                     
        ib_bth.dqpn         : exact;                                                            
        md.startAddr_48_32 : exact;                                                            
        md.startAddr_32_12 : range;                                                            
    }                                                                                           
    actions {                                                                                   
        nop;                                                                                    
        set_start_grpId_objMask;                                                             
    }                                                                                           
    //default_action : nop;                                                                       
    size : 4400;                                                                                 
}

table start_small_addr_to_grpId_objMask {                                                      
    reads {                                                                                     
        ib_bth.dqpn         : exact;                                                           
        md.startAddr_48_20 : exact;                                                            
        md.startAddr_20_12 : range;                                                            
    }                                                                                           
    actions {                                                                                   
        nop;                                                                                    
        set_start_grpId_objMask;                                                             
    }                                                                                           
    //default_action : nop;                                                                       
    size : 4050;                                                                                
}

table start_singlePage_addr_to_grpId_objMask {                                                 
    reads {                                                                                     
        ib_bth.dqpn         : exact;                                                            
        md.startAddr_48_20 : exact;                                                            
        md.startAddr_20_12 : exact;                                                            
    }                                                                                           
    actions {                                                                                   
        nop;                                                                                    
        set_start_grpId_objMask;                                                             
    }                                                                                           
    //default_action : nop;                                                                       
    size : 32000;                                                                                
}    

table end_large_addr_to_grpId_objMask {                                                      
    reads {                                                                                     
        ib_bth.dqpn         : exact;                                                            
        md.endAddr_48_32 : range;                                                            
    }                                                                                           
    actions {                                                                                   
        nop;                                                                                    
        set_end_grpId_objMask;                                                             
    }                                                                                           
    //default_action : nop;                                                                       
    size : 2450;                                                                                 
}

table end_medium_addr_to_grpId_objMask {                                                     
    reads {                                                                                     
        ib_bth.dqpn         : exact;                                                            
        md.endAddr_48_32 : exact;                                                            
        md.endAddr_32_12 : range;                                                            
    }                                                                                           
    actions {                                                                                   
        nop;                                                                                    
        set_end_grpId_objMask;                                                             
    }                                                                                           
    //default_action : nop;                                                                       
    size : 4400;                                                                                 
}

table end_small_addr_to_grpId_objMask {                                                      
    reads {                                                                                     
        ib_bth.dqpn         : exact;                                                           
        md.endAddr_48_20 : exact;                                                            
        md.endAddr_20_12 : range;                                                            
    }                                                                                           
    actions {                                                                                   
        nop;                                                                                    
        set_end_grpId_objMask;                                                             
    }                                                                                           
    //default_action : nop;                                                                       
    size : 4050;                                                                                
}

table end_singlePage_addr_to_grpId_objMask {                                                 
    reads {                                                                                     
        ib_bth.dqpn         : exact;                                                            
        md.endAddr_48_20 : exact;                                                            
        md.endAddr_20_12 : exact;                                                            
    }                                                                                           
    actions {                                                                                   
        nop;                                                                                    
        set_end_grpId_objMask;                                                             
    }                                                                                           
    //default_action : nop;                                                                       
    size : 32000;                                                                                
}

/*===============================================================================================*/
/* Set obj id based on priority P */

table set_objId1_tab {                                                                      
    actions {                                                                                   
        set_objId1;                                                                           
    }                                                                                           
    //default_action : set_objId1;                                                              
}                                                                                               
                                                                                                
action set_objId1() {                                                                         
    modify_field(md.objId, md.start_priority1);                                               
}

table set_objId2_tab {                                                                      
    actions {                                                                                   
        set_objId2;                                                                           
    }                                                                                           
    //default_action : set_objId2;                                                              
}                                                                                               
                                                                                                
action set_objId2() {                                                                         
    modify_field(md.objId, md.start_priority2);                                               
}

table set_objId3_tab {                                                                      
    actions {                                                                                   
        set_objId3;                                                                           
    }                                                                                           
    //default_action : set_objId3;                                                              
}                                                                                               
                                                                                                
action set_objId3() {                                                                         
    modify_field(md.objId, md.start_priority3);                                               
}

primitive_action detect();

table detection1 {                                                                      
    actions {                                                                                   
        detect1;                                                                           
    }                                                                                           
    //default_action : set_objId3;                                                              
}                                                                                               
                                                                                                
action detect1() {                                                                         
    detect();                                               
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
/* Ingress */


control ingress {
    // Stage 0    
	apply(forward);
    
     if (valid(ib_reth)) {
        // Stage 0, 1
        apply(to_48bit_rdma_len);
        apply(split_startAddr_tab);
        apply(cal_rdma_end);
        
        //Stage 2
        apply(start_large_addr_to_grpId_objMask);

        //Stage 3
        apply(split_endAddr_tab);

        //Stage 4
        apply(start_medium_addr_to_grpId_objMask);

        // Stage 5 
        apply(start_small_addr_to_grpId_objMask);
        apply(start_singlePage_addr_to_grpId_objMask);

        // Stage 6-9 
        apply(end_large_addr_to_grpId_objMask);
        apply(end_medium_addr_to_grpId_objMask);
        apply(end_small_addr_to_grpId_objMask);
        apply(end_singlePage_addr_to_grpId_objMask);

        if (md.start_priority1 == md.end_priority1) {
            apply(set_objId1_tab);
        } else if (md.start_priority2 == md.end_priority2) {
            apply(set_objId2_tab);
        } else if (md.start_priority3 == md.end_priority3) {
            apply(set_objId3_tab);
        }
        //apply(detection1);
        apply(rdma_acl);
    }
    
}