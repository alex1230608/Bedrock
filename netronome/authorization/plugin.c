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
__volatile __export __addr40 __imem int16_t start;
__volatile __export __addr40 __imem int16_t end;
__volatile __export __addr40 __imem uint16_t sp;
__volatile __export __addr40 __imem uint16_t ep;
__volatile __export __addr40 __imem uint32_t dqpn;

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

int pif_plugin_tstamp(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{    
     uint32_t temp = pif_plugin_meta_get__intrinsic_metadata__ingress_global_timestamp__1(headers);
     temp = temp / 750000000;
     temp = temp & (0x100000000 - 1);
     pif_plugin_meta_set__md__tstamp(headers, temp);
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_split_start(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
     //md.cmin_win0
     //md.cmin_win0_32_20
     PIF_PLUGIN_ib_reth_T* reth = pif_plugin_hdr_get_ib_reth(headers);
     uint64_t temp = reth->__virtAddr_l_1;
     uint64_t temp_t = reth->virtAddr_l;
     temp +=  temp_t << 32;
     //temps = temp;
     {
     uint64_t temp1 = (temp << 44) >> 44;
     uint64_t temp2 = (temp << 32) >> 32;
     uint64_t temp3 = ((temp << 16) >> 36);
     uint64_t temp4 = ((temp << 16) >> 48);
     uint64_t temp5 = ((temp << 32) >> 44);
     uint64_t temp6 = ((temp << 44) >> 56);
     pif_plugin_meta_set__md__startAddr_20_0(headers, temp1);
     pif_plugin_meta_set__md__startAddr_32_0(headers, temp2);
     pif_plugin_meta_set__md__startAddr_48_20(headers, temp3);
     pif_plugin_meta_set__md__startAddr_48_32(headers, temp4);
     //startAddr_48_32 = reth->__virtAddr_l_1;
     //startAddr_48_32_1 = reth->virtAddr_l;
     start = pif_plugin_meta_get__md__startAddr_48_32(headers);
     pif_plugin_meta_set__md__startAddr_32_12(headers, temp5);
     pif_plugin_meta_set__md__startAddr_20_12(headers, temp6);}
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_split_end(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
     //md.cmin_win0
     //md.cmin_win0_32_20
     //PIF_PLUGIN_ib_reth_T* reth = pif_plugin_hdr_get_ib_reth(headers);
     uint64_t temp = pif_plugin_meta_get__md__rdma_end_l__0(headers);
     uint64_t temp_t = pif_plugin_meta_get__md__rdma_end_l__1(headers);
     temp += temp_t << 32;
     {
     uint64_t temp1 = (temp << 44) >> 44;
     uint64_t temp2 = (temp << 32) >> 32;
     uint64_t temp3 = ((temp << 16) >> 36);
     uint64_t temp4 = ((temp << 16) >> 48);
     uint64_t temp5 = ((temp << 32) >> 44);
     uint64_t temp6 = ((temp << 44) >> 56);
     pif_plugin_meta_set__md__endAddr_20_0(headers, temp1);
     pif_plugin_meta_set__md__endAddr_32_0(headers, temp2);
     pif_plugin_meta_set__md__endAddr_48_20(headers, temp3);
     pif_plugin_meta_set__md__endAddr_48_32(headers, temp4);
     end = pif_plugin_meta_get__md__endAddr_48_32(headers);
     pif_plugin_meta_set__md__endAddr_32_12(headers, temp5);
     pif_plugin_meta_set__md__endAddr_20_12(headers, temp6);}
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_detect(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ib_bth_T* bth = pif_plugin_hdr_get_ib_bth(headers);
    dqpn = bth->dqpn;
    sp = pif_plugin_meta_get__md__start_priority1(headers);
    ep = pif_plugin_meta_get__md__end_priority1(headers);
    return PIF_PLUGIN_RETURN_FORWARD;
}