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

// Template parser.p4 file for basic_switching
// Edit this file as needed for your P4 program

// This parses an ethernet header

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800

parser parse_ethernet {
    extract(ethernet);
    return select(ethernet.etherType) {
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

#define IP_PROTOCOLS_UDP 17

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        IP_PROTOCOLS_UDP : parse_udp;
        default: ingress;
    }
}

parser parse_vlan {
    extract(vlan);
    return select(vlan.etherType) {
        // ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

#define UDP_PORT_IB 4791
#define UDP_PORT_LOG 12345
#define UDP_PORT_CTRL 12347
#define UDP_PORT_TMP_CRC 12348
#define UDP_PORT_AUTH_CTRL 12349

parser parse_udp {
    extract(udp);
    // set_metadata(md.another_udp_len, udp.hdr_length);
    return select(udp.dstPort) {
       UDP_PORT_TMP_CRC   : parse_tmp_crc;
       UDP_PORT_IB        : parse_ib_bth;
       UDP_PORT_LOG       : parse_ib_bth;
       UDP_PORT_CTRL      : parse_ctrl;
       UDP_PORT_AUTH_CTRL : parse_authCtrl;
       default: ingress;
    }
}

parser parse_tmp_crc {
    extract(tmp_crc);
    return parse_ib_bth;
}

#define IB_OPCODE_RC_WRITE_ONLY  10
#define IB_OPCODE_RC_WRITE_FIRST 6
#define IB_OPCODE_RC_READ_REQ    12
#define IB_OPCODE_RC_SEND_ONLY 4
#define IB_OPCODE_UD_SEND_ONLY 100

parser parse_ib_bth {
    extract(ib_bth);
    return select (ib_bth.opCode) {
      IB_OPCODE_RC_WRITE_ONLY  : parse_ib_reth;
      IB_OPCODE_RC_WRITE_FIRST : parse_ib_reth;
      IB_OPCODE_RC_READ_REQ    : parse_ib_reth;
      IB_OPCODE_UD_SEND_ONLY   : parse_ib_deth;
      default: ingress;
    }
}

parser parse_ib_reth {
    extract(ib_reth);
    set_metadata(md.one_48, 1);
    // set_metadata(md.ipv4_protocol_udp_16, 0x0011);
    return select(udp.dstPort) {
       UDP_PORT_LOG     : parse_log_header;
       default: ingress;
    }
}

parser parse_ib_deth {
    extract(ib_deth);
    return select(ib_deth.srcQp) {
       1 : parse_ib_mad;
       default: ingress;
    }
}

parser parse_ib_mad {
    extract(ib_mad);
    return ingress;
}

parser parse_log_header {
    extract(log_header);
    return ingress;
}

parser parse_ctrl {
    extract(ctrl);
    return ingress;
}

parser parse_authCtrl {
    extract(authCtrl);
    return ingress;
}
