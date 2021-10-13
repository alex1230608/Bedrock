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
//=============================================================================================================
#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include "pif_plugin.h"
#include <std/hash.h>

__export __addr40 __imem int64_t time_register[1];
__export __addr40 __imem int64_t time_total[1];
__export __addr40 __imem int64_t packet_total[1];
__export __addr40 __imem int64_t packet_total[1];
__volatile __export __addr40 __imem int32_t startAddr_48_32;
__volatile __export __addr40 __imem int16_t startAddr_48_32_1;
__volatile __export __addr40 __imem int64_t start;
__volatile __export __addr40 __imem int64_t start1;
__volatile __export __addr40 __imem int64_t end;
__volatile __export __addr40 __imem uint16_t sp;
__volatile __export __addr40 __imem uint16_t ep;
__volatile __export __addr40 __imem uint32_t dqpn;
__volatile __export __addr40 __imem uint32_t dqpn;
__volatile __export __addr40 __imem uint32_t log0_byte0;
__volatile __export __addr40 __imem uint32_t log0_byte4;
__volatile __export __addr40 __imem uint32_t log0_byte8;
__volatile __export __addr40 __imem uint32_t log0_byte12;
__volatile __export __addr40 __imem uint32_t log1_byte0;
__volatile __export __addr40 __imem uint32_t log1_byte4;
__volatile __export __addr40 __imem uint32_t log1_byte8;
__volatile __export __addr40 __imem uint32_t log1_byte12;
__volatile __export __addr40 __imem uint32_t log2_byte0;
__volatile __export __addr40 __imem uint32_t log2_byte4;
__volatile __export __addr40 __imem uint32_t log2_byte8;
__volatile __export __addr40 __imem uint32_t log2_byte12;
__volatile __export __addr40 __imem uint32_t log3_byte0;
__volatile __export __addr40 __imem uint32_t log3_byte4;
__volatile __export __addr40 __imem uint32_t log3_byte8;
__volatile __export __addr40 __imem uint32_t log3_byte12;
__volatile __export __addr40 __imem uint32_t log4_byte0;
__volatile __export __addr40 __imem uint32_t log4_byte4;
__volatile __export __addr40 __imem uint32_t log4_byte8;
__volatile __export __addr40 __imem uint32_t log4_byte12;
__volatile __export __addr40 __imem uint32_t log5_byte0;
__volatile __export __addr40 __imem uint32_t log5_byte4;
__volatile __export __addr40 __imem uint32_t log5_byte8;
__volatile __export __addr40 __imem uint32_t log5_byte12;
__volatile __export __addr40 __imem uint32_t log6_byte0;
__volatile __export __addr40 __imem uint32_t log6_byte4;
__volatile __export __addr40 __imem uint32_t log6_byte8;
__volatile __export __addr40 __imem uint32_t log6_byte12;
__volatile __export __addr40 __imem uint32_t log7_byte0;
__volatile __export __addr40 __imem uint32_t log7_byte4;
__volatile __export __addr40 __imem uint32_t log7_byte8;
__volatile __export __addr40 __imem uint32_t log7_byte12;
__volatile __export __addr40 __imem int32_t banned_list1[10];
__volatile __export __addr40 __imem int32_t banned_list2[10];
__volatile __export __addr40 __imem int32_t index;
__volatile __export __addr40 __imem int32_t banned1;
__volatile __export __addr40 __imem int32_t shut1;
__volatile __export __addr40 __imem int32_t log0;
__volatile __export __addr40 __imem int32_t log1;
__volatile __export __addr40 __imem int8_t cursor1;
__volatile __export __addr40 __imem int32_t correct1;
__volatile __export __addr40 __imem int32_t a1;
__volatile __export __addr40 __imem int32_t a2;
__volatile __export __addr40 __imem int32_t a3;
__volatile __export __addr40 __imem int32_t a4;
__lmem int8_t cursor2;
#define CMIN_SIZE 0x10000
//=============================================================================================================
//=============================================================================================================
int pif_plugin_primitive_timestamp(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    __xwrite uint64_t init_high;
    __xwrite uint64_t init_low;
    uint64_t timestamp_high;
    uint64_t timestamp_low;
    __xread uint64_t in_xfer;
	__gpr uint64_t out_reg0, out_reg1, out_reg2;
	__xwrite uint64_t out_xfer;

    //init_high = local_csr_read(local_csr_timestamp_high) - pif_plugin_meta_get__intrinsic_metadata__ingress_global_timestamp__1(headers);
    //init_low = local_csr_read(local_csr_timestamp_low) - pif_plugin_meta_get__intrinsic_metadata__ingress_global_timestamp__0(headers);
    out_reg0 = 0;
    out_reg0 += local_csr_read(local_csr_timestamp_high) - pif_plugin_meta_get__intrinsic_metadata__ingress_global_timestamp__1(headers);
    out_reg0 = out_reg0 << 32;
    out_reg0 += local_csr_read(local_csr_timestamp_low) - pif_plugin_meta_get__intrinsic_metadata__ingress_global_timestamp__0(headers);
    out_xfer = out_reg0;
    mem_write_atomic(&out_xfer, &time_register[0], sizeof(uint64_t));
    
    mem_read_atomic(&in_xfer, &time_total[0], sizeof(uint64_t));
    out_reg1 = 0;
	out_reg1 += in_xfer;
	out_reg1 += (out_reg0 << 32) >> 32;
	out_xfer = out_reg1;
	mem_write_atomic(&out_xfer, &time_total[0], sizeof(uint64_t));

    mem_read_atomic(&in_xfer, &packet_total[0], sizeof(uint64_t));
	out_reg2 = in_xfer;
	out_reg2 += 1;
	out_xfer = out_reg2;
	mem_write_atomic(&out_xfer, &packet_total[0], sizeof(uint64_t));

    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_exit(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
     return PIF_PLUGIN_RETURN_DROP;
}
/*
int pif_plugin_tstamp(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{    
     uint32_t temp = pif_plugin_meta_get__intrinsic_metadata__ingress_global_timestamp__1(headers);
     temp = temp / 750000000;
     temp = temp & (0x100000000 - 1);
     pif_plugin_meta_set__md__tstamp(headers, temp);
     return PIF_PLUGIN_RETURN_FORWARD;
}
*/

int pif_plugin_tstamp(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{    
     PIF_PLUGIN_ipv4_T* ipv4 = pif_plugin_hdr_get_ipv4(headers);
     uint32_t temp = local_csr_read(local_csr_timestamp_low);
     //temp = temp / 750000000;
     //temp = temp & (0x100000000 - 1);
     temp = temp >> 13;
     pif_plugin_meta_set__md__tstamp(headers, temp);
     //start = reth->__virtAddr_l_1;
     start += 1;
     //ipv4->ttl -= 1;
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_tstamp1(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{    
     //PIF_PLUGIN_ib_reth_T* reth = pif_plugin_hdr_get_ib_reth(headers);
     uint32_t temp = local_csr_read(local_csr_timestamp_low);
     temp = temp / 750000000;
     temp = temp & (0x100000000 - 1);
     pif_plugin_meta_set__md__tstamp(headers, temp);
     //start = reth->__virtAddr_l_1;
     start1 += 1;
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_cursor_update(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    //uint8_t temp = pif_plugin_meta_get__md__cursor(headers); //cursor logic is wrong!!
    cursor2 = cursor1;
    if (cursor2 < 7) {
        cursor2 = cursor2+1;
    } else {
        cursor2 = 0;
    }
    cursor1 = cursor2;
    pif_plugin_meta_set__md__cursor(headers, cursor2);
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_form_log(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ib_bth_T* bth = pif_plugin_hdr_get_ib_bth(headers);
    PIF_PLUGIN_ib_reth_T* reth = pif_plugin_hdr_get_ib_reth(headers);
    uint32_t opCode = bth->opCode;
    //uint32_t dqpn = bth->dqpn + opCode<<24;
    uint32_t dqpn = bth->dqpn;
    uint64_t virtAddr_h = reth->virtAddr_h;
    uint64_t virtAddr_h_l = reth->virtAddr_l;
    uint64_t virtAddr_l = reth->__virtAddr_l_1;
    uint32_t tstamp = pif_plugin_meta_get__md__tstamp(headers);
    dqpn += opCode<<24;
    virtAddr_l += virtAddr_h<<48;
    virtAddr_l += virtAddr_h_l<<32;
    //end = dqpn;
    pif_plugin_meta_set__md__log_byte0(headers, tstamp);
    pif_plugin_meta_set__md__log_byte4(headers, dqpn);
    pif_plugin_meta_set__md__log_byte8(headers, virtAddr_l>>32);
    pif_plugin_meta_set__md__log_byte12(headers, (virtAddr_l<<32)>>32);
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_log_byte(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_log_header_T* log_header = pif_plugin_hdr_get_log_header(headers);
    uint8_t temp = cursor1;
    //log1 += 1;
    //start += 1;
    //end = temp;
    if (cursor2 == 0) {
        log0 += 1;
        log0_byte0 = pif_plugin_meta_get__md__log_byte0(headers);
        log0_byte4 = pif_plugin_meta_get__md__log_byte4(headers);
        log0_byte8 = pif_plugin_meta_get__md__log_byte8(headers);
        log0_byte12 = pif_plugin_meta_get__md__log_byte12(headers);
    }
    if (cursor2 == 1) {
        log1 += 1;
        log1_byte0 = pif_plugin_meta_get__md__log_byte0(headers);
        log1_byte4 = pif_plugin_meta_get__md__log_byte4(headers);
        log1_byte8 = pif_plugin_meta_get__md__log_byte8(headers);
        log1_byte12 = pif_plugin_meta_get__md__log_byte12(headers);
    }    
    if (cursor2 == 2) {
        log2_byte0 = pif_plugin_meta_get__md__log_byte0(headers);
        log2_byte4 = pif_plugin_meta_get__md__log_byte4(headers);
        log2_byte8 = pif_plugin_meta_get__md__log_byte8(headers);
        log2_byte12 = pif_plugin_meta_get__md__log_byte12(headers);
    }
    if (cursor2 == 3) {
        log3_byte0 = pif_plugin_meta_get__md__log_byte0(headers);
        log3_byte4 = pif_plugin_meta_get__md__log_byte4(headers);
        log3_byte8 = pif_plugin_meta_get__md__log_byte8(headers);
        log3_byte12 = pif_plugin_meta_get__md__log_byte12(headers);
    }   
    if (cursor2 == 4) {
        log4_byte0 = pif_plugin_meta_get__md__log_byte0(headers);
        log4_byte4 = pif_plugin_meta_get__md__log_byte4(headers);
        log4_byte8 = pif_plugin_meta_get__md__log_byte8(headers);
        log4_byte12 = pif_plugin_meta_get__md__log_byte12(headers);
    }
    if (cursor2 == 5) {
        log5_byte0 = pif_plugin_meta_get__md__log_byte0(headers);
        log5_byte4 = pif_plugin_meta_get__md__log_byte4(headers);
        log5_byte8 = pif_plugin_meta_get__md__log_byte8(headers);
        log5_byte12 = pif_plugin_meta_get__md__log_byte12(headers);
    }    
    if (cursor2 == 6) {
        log6_byte0 = pif_plugin_meta_get__md__log_byte0(headers);
        log6_byte4 = pif_plugin_meta_get__md__log_byte4(headers);
        log6_byte8 = pif_plugin_meta_get__md__log_byte8(headers);
        log6_byte12 = pif_plugin_meta_get__md__log_byte12(headers);
    }
    if (cursor2 == 7) {
        log7_byte0 = pif_plugin_meta_get__md__log_byte0(headers);
        log7_byte4 = pif_plugin_meta_get__md__log_byte4(headers);
        log7_byte8 = pif_plugin_meta_get__md__log_byte8(headers);
        log7_byte12 = pif_plugin_meta_get__md__log_byte12(headers);
    }
    if (cursor2 == 0){
        //log0 += 1;
        //log_header->log0_byte0 = 100;
        log_header->log0_byte0 = log0_byte0;
        log_header->log0_byte4 = log0_byte4;
        log_header->log0_byte8 = log0_byte8;
        log_header->log0_byte12 = log0_byte12;
        //log_header->log1_byte0 = 100;
        log_header->log1_byte0 = log1_byte0;
        log_header->log1_byte4 = log1_byte4;
        log_header->log1_byte8 = log1_byte8;
        log_header->log1_byte12 = log1_byte12;
        log_header->log2_byte0 = log2_byte0;
        log_header->log2_byte4 = log2_byte4;
        log_header->log2_byte8 = log2_byte8;
        log_header->log2_byte12 = log2_byte12;
        log_header->log3_byte0 = log3_byte0;
        log_header->log3_byte4 = log3_byte4;
        log_header->log3_byte8 = log3_byte8;
        log_header->log3_byte12 = log3_byte12;
        log_header->log4_byte0 = log4_byte0;
        log_header->log4_byte4 = log4_byte4;
        log_header->log4_byte8 = log4_byte8;
        log_header->log4_byte12 = log4_byte12;
        log_header->log5_byte0 = log5_byte0;
        log_header->log5_byte4 = log5_byte4;
        log_header->log5_byte8 = log5_byte8;
        log_header->log5_byte12 = log5_byte12;
        log_header->log6_byte0 = log6_byte0;
        log_header->log6_byte4 = log6_byte4;
        log_header->log6_byte8 = log6_byte8;
        log_header->log6_byte12 = log6_byte12;
        log_header->log7_byte0 = log7_byte0;
        log_header->log7_byte4 = log7_byte4;
        log_header->log7_byte8 = log7_byte8;
        log_header->log7_byte12 = log7_byte12;
    } 
    
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_shut(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ctrl_T* ctrl = pif_plugin_hdr_get_ctrl(headers);
    PIF_PLUGIN_ipv4_T* ipv4 = pif_plugin_hdr_get_ipv4(headers);
    int i, j, flag = 0, index_temp = index;
    shut1 += 1;
    for (i=0; i<index_temp; i++){
        if (ctrl->banned_dqpn == banned_list1[i] && ipv4->dstAddr == banned_list2[i]){
            return PIF_PLUGIN_RETURN_FORWARD;
        }
    }
    if (index < 9){
        index += 1;
    }
    index_temp = index;
    banned_list1[index_temp] = ctrl->banned_dqpn;
    banned_list2[index_temp] = ipv4->dstAddr;
    a1 = ctrl->banned_dqpn;
    a2 = ipv4->dstAddr;
    //shut1 += 1;
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_banned(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ib_bth_T* ib_bth = pif_plugin_hdr_get_ib_bth(headers);
    PIF_PLUGIN_ipv4_T* ipv4 = pif_plugin_hdr_get_ipv4(headers);
    int i, j, flag = 0, index_temp = index;
    for (i=0; i<index_temp; i++){
        if (ib_bth->dqpn == banned_list1[i]){
            pif_plugin_meta_set__meta__drop1(headers, 1);
            banned1 += 1;
            return PIF_PLUGIN_RETURN_DROP;
        }
    }
    a3 = ib_bth->dqpn;
    a4 = ipv4->dstAddr;
    //banned1 += 1;
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_corrects(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    correct1 += 1;
    return PIF_PLUGIN_RETURN_FORWARD;
}