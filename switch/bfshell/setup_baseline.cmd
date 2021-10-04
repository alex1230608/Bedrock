pd-baseline

pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.1 action_egress_spec 48
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.2 action_egress_spec 0
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.5 action_egress_spec 15
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.6 action_egress_spec 61
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.10 action_egress_spec 40

pd acl add_entry nop ethernet_dstAddr 0 ethernet_dstAddr_mask 0 ethernet_srcAddr 0 ethernet_srcAddr_mask 0 priority 100

dump_table forward
dump_table acl

exit

