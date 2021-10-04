pd-bedrock-logging

pd forward_reth add_entry set_mc md_cursor 0 md_cursor_mask 0xFF ipv4_dstAddr 10.0.8.1 priority 10 action_grp 667
pd forward_reth add_entry set_mc md_cursor 0 md_cursor_mask 0xFF ipv4_dstAddr 10.0.8.2 priority 10 action_grp 668
pd forward_reth add_entry set_mc md_cursor 0 md_cursor_mask 0xFF ipv4_dstAddr 10.0.8.5 priority 10 action_grp 669

pd forward_reth add_entry set_mc md_cursor 0 md_cursor_mask 0x0 ipv4_dstAddr 10.0.8.1 priority 100 action_grp 670
pd forward_reth add_entry set_mc md_cursor 0 md_cursor_mask 0x0 ipv4_dstAddr 10.0.8.2 priority 100 action_grp 671
pd forward_reth add_entry set_mc md_cursor 0 md_cursor_mask 0x0 ipv4_dstAddr 10.0.8.5 priority 100 action_grp 672
pd forward_reth add_entry set_mc md_cursor 0 md_cursor_mask 0x0 ipv4_dstAddr 10.0.8.6 priority 100 action_grp 673

pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.1 action_egress_spec 48
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.2 action_egress_spec 0
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.5 action_egress_spec 15
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.6 action_egress_spec 61

pd add_logHeader_tab add_entry add_logHeader md_cursor 0

pd remove_logHeader_tab add_entry remove_logHeader ipv4_dstAddr 10.0.8.1 eg_intr_md_egress_port 48
pd remove_logHeader_tab add_entry remove_logHeader ipv4_dstAddr 10.0.8.2 eg_intr_md_egress_port 0
pd remove_logHeader_tab add_entry remove_logHeader ipv4_dstAddr 10.0.8.5 eg_intr_md_egress_port 15

pd remove_logHeader_tab add_entry correct_logHeader ipv4_dstAddr 10.0.8.1 eg_intr_md_egress_port 61 action_macSrc 0x001122334455 action_macDst 0xd8c497724b55 action_ipSrc 10.0.8.10 action_ipDst 10.0.8.6
pd remove_logHeader_tab add_entry correct_logHeader ipv4_dstAddr 10.0.8.2 eg_intr_md_egress_port 61 action_macSrc 0x001122334455 action_macDst 0xd8c497724b55 action_ipSrc 10.0.8.10 action_ipDst 10.0.8.6
pd remove_logHeader_tab add_entry correct_logHeader ipv4_dstAddr 10.0.8.5 eg_intr_md_egress_port 61 action_macSrc 0x001122334455 action_macDst 0xd8c497724b55 action_ipSrc 10.0.8.10 action_ipDst 10.0.8.6

exit

pd ipv4_id_counter_tab add_entry read_update_ipv4_id_counter log_header_valid 1 ipv4_dstAddr 10.0.8.1 eg_intr_md_egress_port 159
pd ipv4_id_counter_tab add_entry read_update_ipv4_id_counter log_header_valid 1 ipv4_dstAddr 10.0.8.2 eg_intr_md_egress_port 159

pd forward_reth add_entry set_egr md_cursor 0 md_cursor_mask 0x0 ipv4_dstAddr 10.0.8.1 priority 100 action_egress_spec 48
pd forward_reth add_entry set_egr md_cursor 0 md_cursor_mask 0x0 ipv4_dstAddr 10.0.8.2 priority 100 action_egress_spec 0
pd forward_reth add_entry set_egr md_cursor 0 md_cursor_mask 0x0 ipv4_dstAddr 10.0.8.5 priority 100 action_egress_spec 15
pd forward_reth add_entry set_egr md_cursor 0 md_cursor_mask 0x0 ipv4_dstAddr 10.0.8.6 priority 100 action_egress_spec 61

