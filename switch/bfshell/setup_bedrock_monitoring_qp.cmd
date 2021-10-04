pd-bedrock-monitoring-qp

pd get_user_id_tab add_entry get_user_id ib_mad_valid 1 ib_mad_attr_id 0x10 ipv4_srcAddr 10.0.8.2 ipv4_dstAddr 10.0.8.1 action_user_id 1
pd get_user_id_tab add_entry get_user_id ib_mad_valid 1 ib_mad_attr_id 0x10 ipv4_srcAddr 10.0.8.5 ipv4_dstAddr 10.0.8.1 action_user_id 2
pd get_user_id_tab add_entry get_user_id ib_mad_valid 1 ib_mad_attr_id 0x10 ipv4_srcAddr 10.0.8.6 ipv4_dstAddr 10.0.8.1 action_user_id 2

pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.1 action_egress_spec 48
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.2 action_egress_spec 0
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.5 action_egress_spec 51
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.6 action_egress_spec 1

pd read_update_cmin_win0_hash0_tab add_entry read_update_cmin_win0_hash0 ib_mad_valid 1 ib_mad_attr_id 0x10 ipv4_dstAddr 10.0.8.1

pd read_update_cmin_win0_hash1_tab add_entry read_update_cmin_win0_hash1 ib_mad_valid 1 ib_mad_attr_id 0x10 ipv4_dstAddr 10.0.8.1

pd read_update_cmin_win0_hash2_tab add_entry read_update_cmin_win0_hash2 ib_mad_valid 1 ib_mad_attr_id 0x10 ipv4_dstAddr 10.0.8.1


pd rate_limit add_entry send_ban_digest ib_mad_valid 1 ib_mad_attr_id 0x10 ipv4_dstAddr 10.0.8.1 md_cmin_win0_20_0_start 0 md_cmin_win0_20_0_end 0xEFFFF priority 100

pd rate_limit add_entry nop ib_mad_valid 1 ib_mad_attr_id 0x10 ipv4_dstAddr 10.0.8.1 md_cmin_win0_20_0_start 0 md_cmin_win0_20_0_end 1000 priority 10

dump_table read_update_cmin_win0_hash0_tab
dump_table read_update_cmin_win0_hash1_tab
dump_table read_update_cmin_win0_hash2_tab
dump_table rate_limit

exit

pd register_read cmin_win0_hash0 index 0xXXXX // crc_16 == CRC_ARC

pd rate_limit add_entry send_ban_digest ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 0 md_cmin_win0 0 md_cmin_win0_mask 0x0 md_cmin_win1 0 md_cmin_win1_mask 0x0 md_cmin_win2 0 md_cmin_win2_mask 0x0 md_cmin_win3 0 md_cmin_win3_mask 0x0 priority 100
pd rate_limit add_entry send_ban_digest ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 1 md_cmin_win0 0 md_cmin_win0_mask 0x0 md_cmin_win1 0 md_cmin_win1_mask 0x0 md_cmin_win2 0 md_cmin_win2_mask 0x0 md_cmin_win3 0 md_cmin_win3_mask 0x0 priority 100
pd rate_limit add_entry send_ban_digest ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 2 md_cmin_win0 0 md_cmin_win0_mask 0x0 md_cmin_win1 0 md_cmin_win1_mask 0x0 md_cmin_win2 0 md_cmin_win2_mask 0x0 md_cmin_win3 0 md_cmin_win3_mask 0x0 priority 100
pd rate_limit add_entry send_ban_digest ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 3 md_cmin_win0 0 md_cmin_win0_mask 0x0 md_cmin_win1 0 md_cmin_win1_mask 0x0 md_cmin_win2 0 md_cmin_win2_mask 0x0 md_cmin_win3 0 md_cmin_win3_mask 0x0 priority 100

pd rate_limit add_entry nop ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 0 md_cmin_win0 0 md_cmin_win0_mask 0xC0000000 md_cmin_win1 0 md_cmin_win1_mask 0x0 md_cmin_win2 0 md_cmin_win2_mask 0x0 md_cmin_win3 0 md_cmin_win3_mask 0x0 priority 10
pd rate_limit add_entry nop ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 1 md_cmin_win0 0 md_cmin_win0_mask 0x0 md_cmin_win1 0 md_cmin_win1_mask 0xC0000000 md_cmin_win2 0 md_cmin_win2_mask 0x0 md_cmin_win3 0 md_cmin_win3_mask 0x0 priority 10
pd rate_limit add_entry nop ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 2 md_cmin_win0 0 md_cmin_win0_mask 0x0 md_cmin_win1 0 md_cmin_win1_mask 0x0 md_cmin_win2 0 md_cmin_win2_mask 0xC0000000 md_cmin_win3 0 md_cmin_win3_mask 0x0 priority 10
pd rate_limit add_entry nop ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 3 md_cmin_win0 0 md_cmin_win0_mask 0x0 md_cmin_win1 0 md_cmin_win1_mask 0x0 md_cmin_win2 0 md_cmin_win2_mask 0x0 md_cmin_win3 0 md_cmin_win3_mask 0xC0000000 priority 10


