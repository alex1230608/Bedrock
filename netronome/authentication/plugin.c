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
__volatile __export __addr40 __imem int64_t start2;
__volatile __lmem int64_t start3;
__volatile __export __addr40 __imem int64_t end;
__volatile __export __addr40 __imem uint16_t sp;
__volatile __export __addr40 __imem uint16_t ep;
__volatile __export __addr40 __imem uint32_t dqpn;
__volatile __export __addr40 __imem uint32_t length;


struct pif_field_list_icrc_payload_list_packed {
    
        uint32_t _raw[12];
 
};

#define CMIN_SIZE 0x10000
//=============================================================================================================
//=============================================================================================================


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
int pif_plugin_diff(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{    
     uint32_t temp = pif_plugin_meta_get__md__diff(headers);
     pif_plugin_meta_set__md__diff0(headers,(temp>>16)&0xFF);
     pif_plugin_meta_set__md__diff1(headers,(temp>>8)&0xFF);
     pif_plugin_meta_set__md__diff2(headers,(temp)&0xFF);
     return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_set_trailer(EXTRACTED_HEADERS_T *headers,
                           MATCH_DATA_T *match_data)
{
    __gpr uint32_t payld_len;
    __gpr uint32_t payld_offset;
    SIGNAL              sig;
    __xwrite uint32_t   write_xfer[8];
    __xread uint32_t    read_xfer[8];
    __gpr uint32_t ctm_payld_len;
    __gpr uint32_t mu_payld_len;
    __mem __addr40 void* payld_base;
    __gpr uint32_t mu_offset;
    //PIF_PLUGIN_tmp_crc_T *tmp_crc;

    payld_offset = pif_pkt_info_spec.pkt_pl_off;
    payld_len = pif_pkt_info_global.p_len - payld_offset;
    if (payld_len >= 4)
    {
        uint32_t temp = pif_plugin_meta_get__md__icrc_tmp4(headers);
        //tmp_crc = pif_plugin_hdr_get_tmp_crc(headers);
        payld_len = payld_len - 4;
        if (pif_pkt_info_global.p_nbi.split)
        {
            ctm_payld_len = (256 << pif_pkt_info_global.p_ctm_size) - pif_pkt_info_global.p_offset - payld_offset;
            mu_payld_len = payld_len - ctm_payld_len;
        }
        else
        {
            ctm_payld_len = payld_len;
            mu_payld_len = 0;
        }
        payld_base = pkt_ctm_ptr40(0, pif_pkt_info_global.p_nbi.pnum, pif_pkt_info_global.p_offset);
        if (mu_payld_len)
        {
            mu_offset = (256 << pif_pkt_info_global.p_ctm_size);
            payld_base = (__mem __addr40 void *)((uint64_t)pif_pkt_info_global.p_nbi.muptr << 11);
        }
        // kuofeng: assuming all 4 bytes of icrc field can either be in ctm or in mu.
        if (pif_pkt_info_global.p_nbi.split) {
            __mem_read8(read_xfer, (__mem __addr40 uint8_t *)((uint64_t)payld_base + mu_offset + mu_payld_len),
                4, 32, ctx_swap, &sig);
        }
        else {
            __mem_read8(read_xfer, (__mem __addr40 uint8_t *)((uint64_t)payld_base + payld_offset + ctm_payld_len),
                4, 32, ctx_swap, &sig);
        }
        start = read_xfer[0];
        //write_xfer[0] = read_xfer[0];
        write_xfer[0] = start3;
        //start1 = temp;
        if (pif_pkt_info_global.p_nbi.split) {
            __mem_write8(write_xfer, (__mem __addr40 uint8_t *)((uint64_t)payld_base + mu_offset + mu_payld_len),
                4, 32, ctx_swap, &sig);
        }
        else {
            __mem_write8(write_xfer, (__mem __addr40 uint8_t *)((uint64_t)payld_base + payld_offset + ctm_payld_len),
                4, 32, ctx_swap, &sig);
        }
    }
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_crc(EXTRACTED_HEADERS_T *headers,
                           MATCH_DATA_T *match_data)
{
    {
            
    //unsigned int _pif_flc_val = icrc_reth_payload_len4(_pif_parrep, _pif_ctldata);
    __lmem struct pif_parrep_ctldata *ctldata = (__lmem struct pif_parrep_ctldata *)(parrep + PIF_PARREP_CTLDATA_OFF_LW);
   
    __gpr uint32_t calc_fld = PIF_FLCALC_CRC32_INIT;
    __lmem struct pif_header_ib_bth *ib_bth = (__lmem struct pif_header_ib_bth *)(parrep + PIF_PARREP_ib_bth_OFF_LW);
    __lmem struct pif_header_md *md = (__lmem struct pif_header_md *)(parrep + PIF_PARREP_md_OFF_LW);
    __lmem struct pif_header_udp *udp = (__lmem struct pif_header_udp *)(parrep + PIF_PARREP_udp_OFF_LW);
    __lmem struct pif_header_ipv4 *ipv4 = (__lmem struct pif_header_ipv4 *)(parrep + PIF_PARREP_ipv4_OFF_LW);
    __lmem struct pif_field_list_icrc_payload_list_packed input_icrc_payload_list;
    __gpr uint32_t payld_offset;
    __gpr uint32_t payld_len;

    input_icrc_payload_list._raw[0] = ((__lmem uint32_t *)md)[20];
    input_icrc_payload_list._raw[1] = ((__lmem uint32_t *)md)[20];
    input_icrc_payload_list._raw[2] = ((ipv4->version) << 28) | ((ipv4->ihl) << 24) | ((md->ones_8) << 16) | ipv4->totalLen;
    input_icrc_payload_list._raw[3] = ((__lmem uint32_t *)ipv4)[1];
    input_icrc_payload_list._raw[4] = ((md->ones_8) << 24) | ((ipv4->protocol) << 16) | md->ones_16;
    input_icrc_payload_list._raw[5] = ((__lmem uint32_t *)ipv4)[3];
    input_icrc_payload_list._raw[6] = ((__lmem uint32_t *)ipv4)[4];
    input_icrc_payload_list._raw[7] = ((__lmem uint32_t *)udp)[0];
    input_icrc_payload_list._raw[8] = ((udp->hdr_length) << 16) | md->ones_16;
    input_icrc_payload_list._raw[9] = ((__lmem uint32_t *)ib_bth)[0];
    input_icrc_payload_list._raw[10] = ((md->ones_8) << 24) | ib_bth->dqpn;
    input_icrc_payload_list._raw[11] = ((__lmem uint32_t *)ib_bth)[2];

    calc_fld = pif_flcalc_crc32_lmem(calc_fld, (__lmem uint32_t *) input_icrc_payload_list._raw, 48);
    
    payld_offset = pif_pkt_info_spec.pkt_pl_off;
    payld_len = pif_pkt_info_global.p_len - payld_offset;
    length = pif_pkt_info_global.p_len;
    if (payld_len >= 4){
        calc_fld = pif_flcalc_crc32(calc_fld, 0, 0, 0, 0, payld_offset, payld_len-4);
    }
    calc_fld = pif_flcalc_crc32_reflect(calc_fld);
    {
    uint32_t calc_fld1, calc_fld2, calc_fld3, calc_fld4;
    calc_fld1 = calc_fld >> 24;
    calc_fld2 = (calc_fld << 8) >> 24;
    calc_fld3 = (calc_fld << 16) >> 24;
    calc_fld4 = (calc_fld << 24) >> 24;
    calc_fld = (calc_fld4 << 24) | (calc_fld3 << 16) | (calc_fld2 << 8) | calc_fld1;
    start1 = calc_fld;
    start3 = calc_fld; //The correct one!
    //start3 = calc_fld+1;
    start2 = md->ones_16;
    }
    //pif_plugin_meta_set__md__icrc_tmp4(headers, _pif_flc_val);
    pif_plugin_meta_set__md__icrc_tmp4(headers, calc_fld);
    //pif_plugin_meta_set__md__icrc_tmp4(headers, calc_fld+1);

    }
    return PIF_PLUGIN_RETURN_FORWARD;
}

/*
input_icrc_reth_payload_len4_list._raw[0] = ((__lmem uint32_t *)md)[20];
    input_icrc_reth_payload_len4_list._raw[1] = ((__lmem uint32_t *)md)[20];
    input_icrc_reth_payload_len4_list._raw[2] = ((ipv4->version) << 28) | ((ipv4->ihl) << 24) | ((md->ones_8) << 16) | ipv4->totalLen;
    input_icrc_reth_payload_len4_list._raw[3] = ((__lmem uint32_t *)ipv4)[1];
    input_icrc_reth_payload_len4_list._raw[4] = ((md->ones_8) << 24) | ((ipv4->protocol) << 16) | md->ones_16;
    input_icrc_reth_payload_len4_list._raw[5] = ((__lmem uint32_t *)ipv4)[3];
    input_icrc_reth_payload_len4_list._raw[6] = ((__lmem uint32_t *)ipv4)[4];
    input_icrc_reth_payload_len4_list._raw[7] = ((__lmem uint32_t *)udp)[0];
    input_icrc_reth_payload_len4_list._raw[8] = ((udp->hdr_length) << 16) | md->ones_16;
    input_icrc_reth_payload_len4_list._raw[9] = ((__lmem uint32_t *)ib_bth)[0];
    input_icrc_reth_payload_len4_list._raw[10] = ((md->ones_8) << 24) | ib_bth->dqpn;
    input_icrc_reth_payload_len4_list._raw[11] = ((__lmem uint32_t *)ib_bth)[2];
    input_icrc_reth_payload_len4_list._raw[12] = ((__lmem uint32_t *)ib_reth)[0];
    input_icrc_reth_payload_len4_list._raw[13] = ((__lmem uint32_t *)ib_reth)[1];
    input_icrc_reth_payload_len4_list._raw[14] = ((__lmem uint32_t *)ib_reth)[2];
    input_icrc_reth_payload_len4_list._raw[15] = ((__lmem uint32_t *)ib_reth)[3];

    calc_fld = pif_flcalc_crc32_lmem(calc_fld, (__lmem uint32_t *) input_icrc_reth_payload_len4_list._raw, 64);
    if (PIF_PARREP_log_header_VALID(ctldata)) {
        __lmem uint8_t * input = (__lmem uint8_t *)(parrep + PIF_PARREP_log_header_OFF_LW);
        calc_fld = pif_flcalc_crc32_lmem(calc_fld, (__lmem uint32_t *) input, PIF_PARREP_log_header_LEN_B);
    }
    if (PIF_PARREP_ctrl_VALID(ctldata)) {
        __lmem uint8_t * input = (__lmem uint8_t *)(parrep + PIF_PARREP_ctrl_OFF_LW);
        calc_fld = pif_flcalc_crc32_lmem(calc_fld, (__lmem uint32_t *) input, PIF_PARREP_ctrl_LEN_B);
    }
    if (PIF_PARREP_authCtrl_VALID(ctldata)) {
        __lmem uint8_t * input = (__lmem uint8_t *)(parrep + PIF_PARREP_authCtrl_OFF_LW);
        calc_fld = pif_flcalc_crc32_lmem(calc_fld, (__lmem uint32_t *) input, PIF_PARREP_authCtrl_LEN_B);
    }
    if (PIF_PARREP_ib_deth_VALID(ctldata)) {
        __lmem uint8_t * input = (__lmem uint8_t *)(parrep + PIF_PARREP_ib_deth_OFF_LW);
        calc_fld = pif_flcalc_crc32_lmem(calc_fld, (__lmem uint32_t *) input, PIF_PARREP_ib_deth_LEN_B);
    }
    if (PIF_PARREP_ib_mad_VALID(ctldata)) {
        __lmem uint8_t * input = (__lmem uint8_t *)(parrep + PIF_PARREP_ib_mad_OFF_LW);
        calc_fld = pif_flcalc_crc32_lmem(calc_fld, (__lmem uint32_t *) input, PIF_PARREP_ib_mad_LEN_B);
    }
*/