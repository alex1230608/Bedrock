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
__volatile __export __addr40 __imem int32_t tstamp_g;
__volatile __export __addr40 __imem int32_t temp_g;
__volatile __export __addr40 __imem int32_t temp0_g;
__volatile __export __addr40 __imem int64_t cmin_g;
__volatile __export __addr40 __imem int32_t cmin_w;
__volatile __export __addr40 __imem int32_t cmin_w1;
__volatile __export __addr40 __imem int16_t ban_list[24];
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

int pif_plugin_hash_function0(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    //PIF_PLUGIN_md_T *md = pif_plugin_hdr_get_md(headers);
    //PIF_PLUGIN_meta_T *meta = pif_plugin_hdr_get_meta(headers);
    //md.user_id
    uint16_t hash_calc;
	uint32_t user_id = pif_plugin_meta_get__md__user_id(headers);
    hash_calc = hash_me_crc32((void *)user_id, sizeof(uint32_t), 1);
    pif_plugin_meta_set__meta__hash_calc(headers, hash_calc & (CMIN_SIZE - 1));
    return PIF_PLUGIN_RETURN_FORWARD;

}

int pif_plugin_hash_function1(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    //PIF_PLUGIN_md_T *md = pif_plugin_hdr_get_md(headers);
    //PIF_PLUGIN_meta_T *meta = pif_plugin_hdr_get_meta(headers);
    //md.user_id
    uint16_t hash_calc;
	uint32_t user_id = pif_plugin_meta_get__md__user_id(headers);
    hash_calc = hash_me_crc32c((void *)user_id, sizeof(uint32_t), 1);
    pif_plugin_meta_set__meta__hash_calc(headers, hash_calc & (CMIN_SIZE - 1));
    return PIF_PLUGIN_RETURN_FORWARD;

}

int pif_plugin_hash_function2(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    //PIF_PLUGIN_md_T *md = pif_plugin_hdr_get_md(headers);
    //PIF_PLUGIN_meta_T *meta = pif_plugin_hdr_get_meta(headers);
    //md.user_id
    uint16_t hash_calc;
	uint32_t user_id = pif_plugin_meta_get__md__user_id(headers);
    hash_calc = hash_me_crc32c((void *)user_id, sizeof(uint32_t), 1) ^ hash_me_crc32((void *)user_id, sizeof(uint32_t), 1);
    pif_plugin_meta_set__meta__hash_calc(headers, hash_calc & (CMIN_SIZE - 1));
    return PIF_PLUGIN_RETURN_FORWARD;

}

int pif_plugin_comp1(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    //min(md.cmin_win0_s1, md.cmin_win0_hash0, md.cmin_win0_hash1);
    //min(md.cmin_win1_s1, md.cmin_win1_hash0, md.cmin_win1_hash1);
    //min(md.cmin_win2_s1, md.cmin_win2_hash0, md.cmin_win2_hash1);
    //min(md.cmin_win3_s1, md.cmin_win3_hash0, md.cmin_win3_hash1);
    //min(md.cmin_win0_s2, md.cmin_win0_hash2, 0xFFFFFFFF);
    //min(md.cmin_win1_s2, md.cmin_win1_hash2, 0xFFFFFFFF);
    //min(md.cmin_win2_s2, md.cmin_win2_hash2, 0xFFFFFFFF);
    //min(md.cmin_win3_s2, md.cmin_win3_hash2, 0xFFFFFFFF);
    uint32_t cmin_win_s, left, right;
    left = pif_plugin_meta_get__md__cmin_win0_hash0(headers);
    right = pif_plugin_meta_get__md__cmin_win0_hash1(headers);
    cmin_win_s = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win0_s1(headers, cmin_win_s);
   
    left = pif_plugin_meta_get__md__cmin_win1_hash0(headers);
    right = pif_plugin_meta_get__md__cmin_win1_hash1(headers);
    cmin_win_s = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win1_s1(headers, cmin_win_s);

    left = pif_plugin_meta_get__md__cmin_win2_hash0(headers);
    right = pif_plugin_meta_get__md__cmin_win2_hash1(headers);
    cmin_win_s = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win2_s1(headers, cmin_win_s);
    
    left = pif_plugin_meta_get__md__cmin_win3_hash0(headers);
    right = pif_plugin_meta_get__md__cmin_win3_hash1(headers);
    cmin_win_s = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win3_s1(headers, cmin_win_s);
    
    left = pif_plugin_meta_get__md__cmin_win0_hash2(headers);
    right = 0xFFFFFFFF;
    cmin_win_s = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win0_s2(headers, cmin_win_s);

    left = pif_plugin_meta_get__md__cmin_win1_hash2(headers);
    right = 0xFFFFFFFF;
    cmin_win_s = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win1_s2(headers, cmin_win_s);
    
    left = pif_plugin_meta_get__md__cmin_win2_hash2(headers);
    right = 0xFFFFFFFF;
    cmin_win_s = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win2_s2(headers, cmin_win_s);

    left = pif_plugin_meta_get__md__cmin_win3_hash2(headers);
    right = 0xFFFFFFFF;
    cmin_win_s = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win3_s2(headers, cmin_win_s);
    return PIF_PLUGIN_RETURN_FORWARD;

}

int pif_plugin_comp2(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    //min(md.cmin_win0, md.cmin_win0_s1, md.cmin_win0_s2);
    //min(md.cmin_win1, md.cmin_win1_s1, md.cmin_win1_s2);
    //min(md.cmin_win2, md.cmin_win2_s1, md.cmin_win2_s2);
    //min(md.cmin_win3, md.cmin_win3_s1, md.cmin_win3_s2);
    uint32_t cmin_win, left, right;
    left = pif_plugin_meta_get__md__cmin_win0_s1(headers);
    right = pif_plugin_meta_get__md__cmin_win0_s2(headers);
    cmin_win = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win0(headers, cmin_win);

    left = pif_plugin_meta_get__md__cmin_win1_s1(headers);
    right = pif_plugin_meta_get__md__cmin_win1_s2(headers);
    cmin_win = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win1(headers, cmin_win);

    left = pif_plugin_meta_get__md__cmin_win2_s1(headers);
    right = pif_plugin_meta_get__md__cmin_win2_s2(headers);
    cmin_win = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win2(headers, cmin_win);

    left = pif_plugin_meta_get__md__cmin_win3_s1(headers);
    right = pif_plugin_meta_get__md__cmin_win3_s2(headers);
    cmin_win = (left < right) ? left : right;
    pif_plugin_meta_set__md__cmin_win3(headers, cmin_win);
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_split0(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
     //md.cmin_win0
     //md.cmin_win0_32_20
     uint32_t temp = pif_plugin_meta_get__md__cmin_win0(headers);
     temp = (temp >> 20) & (0x1000 - 1);
     pif_plugin_meta_set__md__cmin_win0_32_20(headers, temp);
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_split1(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
     //md.cmin_win0
     //md.cmin_win0_32_20
     uint32_t temp = pif_plugin_meta_get__md__cmin_win1(headers);
     temp = (temp >> 20) & (0x1000 - 1);
     pif_plugin_meta_set__md__cmin_win1_32_20(headers, temp);
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_split2(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
     //md.cmin_win0
     //md.cmin_win0_32_20
     uint32_t temp = pif_plugin_meta_get__md__cmin_win2(headers);
     temp = (temp >> 20) & (0x1000 - 1);
     pif_plugin_meta_set__md__cmin_win2_32_20(headers, temp);
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_split3(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
     //md.cmin_win0
     //md.cmin_win0_32_20
     uint32_t temp = pif_plugin_meta_get__md__cmin_win3(headers);
     temp = (temp >> 20) & (0x1000 - 1);
     pif_plugin_meta_set__md__cmin_win3_32_20(headers, temp);
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_exit(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
     return PIF_PLUGIN_RETURN_DROP;
}

int pif_plugin_tstamp(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{    
     uint32_t temp = local_csr_read(local_csr_timestamp_low);
     //uint32_t temp_p = pif_plugin_meta_get__md__tstamp(headers);
     //temp0_g = local_csr_read(local_csr_timestamp_low);
     temp_g = temp>>26;
     temp = temp>>26; 
     pif_plugin_meta_set__md__tstamp(headers, temp);
     //cmin_win1_hash0[0] = 0;
     if (tstamp_g != temp && temp != temp0_g){
         cmin_g += 1;
         temp0_g = temp;
         
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win0_hash0 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win0_hash0 *) &pif_register_cmin_win0_hash0[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win0_hash1 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win0_hash1 *) &pif_register_cmin_win0_hash1[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win0_hash2 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win0_hash2 *) &pif_register_cmin_win0_hash2[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win1_hash0 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win1_hash0 *) &pif_register_cmin_win1_hash0[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win1_hash1 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win1_hash1 *) &pif_register_cmin_win1_hash1[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win1_hash2 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win1_hash2 *) &pif_register_cmin_win1_hash2[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win2_hash0 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win2_hash0 *) &pif_register_cmin_win2_hash0[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win2_hash1 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win2_hash1 *) &pif_register_cmin_win2_hash1[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win2_hash2 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win2_hash2 *) &pif_register_cmin_win2_hash2[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win3_hash0 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win3_hash0 *) &pif_register_cmin_win3_hash0[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win3_hash1 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win3_hash1 *) &pif_register_cmin_win3_hash1[_pif_index];
                _pif_xreg[0] = 0;
                mem_write8(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
         {
            unsigned int _pif_index;
            for (_pif_index = 0;_pif_index < 65536;_pif_index++) {
                __xwrite uint32_t _pif_xreg[1];   
                __mem __addr40 struct pif_header_cmin_win3_hash2 *_pif_hdrptr = (__mem __addr40 struct pif_header_cmin_win3_hash2 *) &pif_register_cmin_win3_hash2[_pif_index];
                _pif_xreg[0] = 0;
                mem_write32(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

            }
         }
     }

     tstamp_g = temp;
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_win_id(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{    
     uint32_t temp = pif_plugin_meta_get__md__winId(headers);
     uint32_t cmin_win;
     if (temp == 0) {
         cmin_win = pif_plugin_meta_get__md__cmin_win0_32_20(headers);
         pif_plugin_meta_set__meta__cmin_win(headers, cmin_win);
     } else if (temp == 1) {
         cmin_win = pif_plugin_meta_get__md__cmin_win1_32_20(headers);
         pif_plugin_meta_set__meta__cmin_win(headers, cmin_win);
     } else if (temp == 2) {
         cmin_win = pif_plugin_meta_get__md__cmin_win2_32_20(headers);
         pif_plugin_meta_set__meta__cmin_win(headers, cmin_win);
     } else if (temp == 3) {
         cmin_win = pif_plugin_meta_get__md__cmin_win3_32_20(headers);
         pif_plugin_meta_set__meta__cmin_win(headers, cmin_win);
     }
     cmin_w = pif_plugin_meta_get__md__cmin_win0(headers);
     cmin_w1 = pif_plugin_meta_get__md__cmin_win1(headers);
     if (pif_plugin_meta_get__md__cmin_win0(headers) >= 0x30000000){
         ban_list[pif_plugin_meta_get__md__user_id(headers)] = 1;
         //return PIF_PLUGIN_RETURN_DROP;
     }
     if(ban_list[pif_plugin_meta_get__md__user_id(headers)] == 1){
         pif_plugin_meta_set__meta__drop1(headers, 1);
         //return PIF_PLUGIN_RETURN_EXIT;
     }
     return PIF_PLUGIN_RETURN_FORWARD;
}