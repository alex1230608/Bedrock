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

// Template headers.p4 file for basic_switching
// Edit this file as needed for your P4 program

// Here's an ethernet header to get started.

header_type ethernet_t {
    fields {
        dstAddr   : 48;
        srcAddr   : 48;
        etherType : 16;
    }
}

header ethernet_t ethernet;

header_type vlan_tag_t {
    fields {
        pcp       : 3;
        cfi       : 1;
        vid       : 12;
        etherType : 16;
    }
}

header vlan_tag_t vlan;

header_type ipv4_t {
    fields {
        version        : 4;
        ihl            : 4;
        diffserv       : 8;
        totalLen       : 16;
        identification : 16;
        flags          : 3;
        fragOffset     : 13;
        ttl            : 8;
        protocol       : 8;
        hdrChecksum    : 16;
        srcAddr        : 32;
        dstAddr        : 32;
    }
}

header ipv4_t ipv4;

header_type udp_t {
    fields {
        srcPort    : 16;
        dstPort    : 16;
        hdr_length : 16;
        checksum   : 16;
    }
}

header udp_t udp;

header_type ib_bth_t {
   fields {
      opCode    : 8;
      se        : 1;
      migReq    : 1;
      padCnt    : 2;
      tver      : 4;
      p_key     : 16;
      reserved  : 8;
      dqpn      : 24;
      ack_req   : 1;
      reserved2 : 7;
      psn       : 24;
   }
}

header ib_bth_t ib_bth;

header_type ib_reth_t {
   fields {
      virtAddr_h : 16;
      virtAddr_l : 48;
      rkey       : 32;
      len        : 32;
   }
}

header ib_reth_t ib_reth;

header_type ib_deth_t {
   fields {
      qKey     : 32;
      reserved : 8;
      srcQp    : 24;
   }
}

header ib_deth_t ib_deth;

header_type ib_mad_t {
   fields {
      base_version  : 8;
      mgmt_class    : 8;
      class_version : 8;
      mad_method    : 8;
      status        : 16;
      specific      : 16;
      trans_id      : 64;
      attr_id       : 16;
      reserved      : 16;
      modifier      : 32;
   }
}

header ib_mad_t ib_mad;

header_type log_header_t {
   fields {
      log0_byte0  : 32;
      log0_byte4  : 32;
      log0_byte8  : 32;
      log0_byte12 : 32;
      log1_byte0  : 32;
      log1_byte4  : 32;
      log1_byte8  : 32;
      log1_byte12 : 32;
      log2_byte0  : 32;
      log2_byte4  : 32;
      log2_byte8  : 32;
      log2_byte12 : 32;
      log3_byte0  : 32;
      log3_byte4  : 32;
      log3_byte8  : 32;
      log3_byte12 : 32;
      log4_byte0  : 32;
      log4_byte4  : 32;
      log4_byte8  : 32;
      log4_byte12 : 32;
      log5_byte0  : 32;
      log5_byte4  : 32;
      log5_byte8  : 32;
      log5_byte12 : 32;
      log6_byte0  : 32;
      log6_byte4  : 32;
      log6_byte8  : 32;
      log6_byte12 : 32;
      log7_byte0  : 32;
      log7_byte4  : 32;
      log7_byte8  : 32;
      log7_byte12 : 32;
   }
}

header log_header_t log_header;

header_type tmp_crc_t {
   fields {
      val : 32;
   }
}
header tmp_crc_t tmp_crc;

header_type ctrl_t {
   fields {
      banned_dqpn : 32;
   }
}
header ctrl_t ctrl;

header_type authCtrl_t {
   fields {
      sip       : 32;
      fake_dqpn : 24;
      real_dqpn : 24;
   }
}
header authCtrl_t authCtrl;

#ifndef CURSOR_WIDTH
#define CURSOR_WIDTH 8
#endif

header_type md_t {
   fields {
      diff  : 24;
      diff0 : 24;
      diff1 : 24;
      diff2 : 24;
      crc_zero  : 32;
      crc_byte0 : 32;
      crc_byte1 : 32;
      crc_byte2 : 32;
      crc_aggr1 : 32;
      crc_aggr2 : 32;

      rdma_len : 48;
      one_48   : 48;

      rdma_end_h : 16;
      rdma_end_l : 48;

      // for idiada aclSepStartEndHierarchy
      startAddr_20_13 : 7;
      endAddr_20_13 : 7;

      // for idiada aclPage
      startAddr_32_13 : 19;
      endAddr_32_13 : 19;

      // for osdi twem aclSepStartEndHierarchy
      startAddr_48_31 : 17;
      startAddr_31_0  : 31;
      startAddr_11_0  : 11;
      startAddr_11_3  : 8;
      startAddr_31_11 : 20;
      endAddr_48_31 : 17;
      endAddr_31_0  : 31;
      endAddr_11_0  : 11;
      endAddr_11_3  : 8;
      endAddr_31_11 : 20;

      // for osdi twem aclPage
      startAddr_23_0  : 23;
      startAddr_48_23 : 25;
      startAddr_23_3  : 20;
      startAddr_48_43 : 5;
      startAddr_43_23 : 20;
      endAddr_23_0    : 23;
      endAddr_48_23   : 25;
      endAddr_23_3    : 20;
      endAddr_48_43   : 5;
      endAddr_43_23   : 20;

      // for arctur aclSepStartEndHierarchy
      startAddr_48_17 : 31;
      startAddr_17_0  : 17;
      startAddr_17_9  : 8;
      endAddr_48_17   : 31;
      endAddr_17_0    : 17;
      endAddr_17_9    : 8;

      // for arctur aclPage
      startAddr_29_0  : 29;
      startAddr_48_29 : 19;
      startAddr_29_9  : 20;
      endAddr_29_0    : 29;
      endAddr_48_29   : 19;
      endAddr_29_9    : 20;

      startAddr_32_0 : 32;
      endAddr_32_0   : 32;

      startAddr_20_0  : 20;
      startAddr_48_20 : 28;
      startAddr_32_12 : 20;
      startAddr_20_12 : 8;
      endAddr_20_0    : 20;
      endAddr_48_20   : 28;
      endAddr_32_12   : 20;
      endAddr_20_12   : 8;

      startAddr_48_32 : 16;
      startAddr_32_16 : 16;
      startAddr_16_0  : 16;
      endAddr_48_32   : 16;
      endAddr_32_16   : 16;
      endAddr_16_0    : 16;

      start_priority1 : 16;
      start_priority2 : 16;
      start_priority3 : 16;
      end_priority1 : 16;
      end_priority2 : 16;
      end_priority3 : 16;

      objId : 16;

      start_grpId   : 16;
      start_objMask : 3;
      start_objId   : 16;
      end_grpId     : 16;
      end_objMask   : 3;
      end_objId     : 16;
      join_objMask  : 3;

      user_id     : 32;
      tstamp      : 32;
      tstamp_diff : 32;
      winId       : 2;
      digest_type : 2;

      cmin_win0_hash0 : 32;
      cmin_win1_hash0 : 32;
      cmin_win2_hash0 : 32;
      cmin_win3_hash0 : 32;
      cmin_win0_hash1 : 32;
      cmin_win1_hash1 : 32;
      cmin_win2_hash1 : 32;
      cmin_win3_hash1 : 32;
      cmin_win0_hash2 : 32;
      cmin_win1_hash2 : 32;
      cmin_win2_hash2 : 32;
      cmin_win3_hash2 : 32;
      cmin_win0_hash3 : 32;
      cmin_win1_hash3 : 32;
      cmin_win2_hash3 : 32;
      cmin_win3_hash3 : 32;

      cmin_win0_s1 : 32;
      cmin_win1_s1 : 32;
      cmin_win2_s1 : 32;
      cmin_win3_s1 : 32;
      cmin_win0_s2 : 32;
      cmin_win1_s2 : 32;
      cmin_win2_s2 : 32;
      cmin_win3_s2 : 32;

      cmin_win0 : 32;
      cmin_win1 : 32;
      cmin_win2 : 32;
      cmin_win3 : 32;

      cmin_win0_32_20 : 12;
      cmin_win1_32_20 : 12;
      cmin_win2_32_20 : 12;
      cmin_win3_32_20 : 12;

      cmin_win0_20_0 : 20;

      cursor     : CURSOR_WIDTH;
      // signal_pop : 8;
      log_byte0  : 32;
      log_byte4  : 32;
      log_byte8  : 32;
      log_byte12 : 32;

      // another_udp_len : 16;
      // zero_8 : 8;
      // ipv4_id : 16;
   }
}

metadata md_t md;
@pragma pa_container ingress md.rdma_len 10 11
@pragma pa_container ingress md.rdma_end_l 12 13

