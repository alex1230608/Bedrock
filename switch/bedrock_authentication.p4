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

// This is P4 sample source for basic_switching

#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>

#include "includes/headers.p4"
#include "includes/parser.p4"

/*===============================================================================================*/
/* Basic port-to-port forwarding */

#define GRP_BROADCAST 666

action set_mc(grp) {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, grp);
}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
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
        set_egr; set_mc;
    }
    default_action : set_mc(GRP_BROADCAST);
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

/*===============================================================================================*/
/* Check ingress port and source IP */

action drop_exit() {
    drop();
    exit();
}

table check_ingress_ip {
    reads {
        ipv4.srcAddr            : exact;
        ig_intr_md.ingress_port : exact;
    }
    actions {
        nop;
        drop_exit;
    }
    default_action: _drop;
    size : 1024;
}

/*===============================================================================================*/
/* Decode the fake dqpn from client to real dqpn */

action change_to_real_dqpn(real_dqpn) {
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
    default_action : drop_exit;
    size : 32768;
}

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
    default_action : nop;
    size : 2;
}


/*===============================================================================================*/
/* Ingress */

control ingress {
    if (valid(authCtrl)) {
        apply(receive_authCtrl);
    } else {
        if (valid(ib_bth) and ib_bth.opCode != 100 and ipv4.dstAddr == 0x0a000801) {
            apply(check_ingress_ip);
            apply(decode_dqpn);
        }
        apply(forward);
    }
}

/*===============================================================================================*/
/* Egress */

control egress {
    apply(acl);
}

