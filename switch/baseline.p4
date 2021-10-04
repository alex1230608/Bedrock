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

#define IP_ADDR_NETRONOME 0x0a00080a
#define IP_ADDR_SERVER    0x0a000801

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
/* Ingress */

control ingress {
    apply(forward);
}

/*===============================================================================================*/
/* Egress */

control egress {
    apply(acl);
}

