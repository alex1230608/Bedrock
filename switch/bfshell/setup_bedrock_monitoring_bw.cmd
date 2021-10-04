pd-bedrock-monitoring-bw

pd get_user_id_tab add_entry get_user_id ib_bth_valid 1 ipv4_srcAddr 10.0.8.2 ipv4_dstAddr 10.0.8.1 action_user_id 1
pd get_user_id_tab add_entry get_user_id ib_bth_valid 1 ipv4_srcAddr 10.0.8.5 ipv4_dstAddr 10.0.8.1 action_user_id 2
pd get_user_id_tab add_entry get_user_id ib_bth_valid 1 ipv4_srcAddr 10.0.8.6 ipv4_dstAddr 10.0.8.1 action_user_id 2

pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.1 action_egress_spec 48
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.2 action_egress_spec 0
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.5 action_egress_spec 15
pd forward add_entry set_egr ipv4_valid 1 ipv4_dstAddr 10.0.8.6 action_egress_spec 61

pd last_time add_entry read_update_ts md_tstamp 0x0000 md_tstamp_mask 0xc000 priority 100 action_winId 0
pd last_time add_entry read_update_ts md_tstamp 0x4000 md_tstamp_mask 0xc000 priority 100 action_winId 1
pd last_time add_entry read_update_ts md_tstamp 0x8000 md_tstamp_mask 0xc000 priority 100 action_winId 2
pd last_time add_entry read_update_ts md_tstamp 0xc000 md_tstamp_mask 0xc000 priority 100 action_winId 3

pd generate_entry_digest_tab add_entry nop md_tstamp_diff 0 md_tstamp_diff_mask 0xFFFFC000 priority 100

pd read_update_cmin_win0_hash0_tab add_entry read_update_cmin_win0_hash0 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 0
pd read_update_cmin_win1_hash0_tab add_entry read_update_cmin_win1_hash0 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 1
pd read_update_cmin_win2_hash0_tab add_entry read_update_cmin_win2_hash0 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 2
pd read_update_cmin_win3_hash0_tab add_entry read_update_cmin_win3_hash0 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 3

pd read_update_cmin_win0_hash1_tab add_entry read_update_cmin_win0_hash1 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 0
pd read_update_cmin_win1_hash1_tab add_entry read_update_cmin_win1_hash1 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 1
pd read_update_cmin_win2_hash1_tab add_entry read_update_cmin_win2_hash1 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 2
pd read_update_cmin_win3_hash1_tab add_entry read_update_cmin_win3_hash1 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 3

pd read_update_cmin_win0_hash2_tab add_entry read_update_cmin_win0_hash2 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 0
pd read_update_cmin_win1_hash2_tab add_entry read_update_cmin_win1_hash2 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 1
pd read_update_cmin_win2_hash2_tab add_entry read_update_cmin_win2_hash2 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 2
pd read_update_cmin_win3_hash2_tab add_entry read_update_cmin_win3_hash2 ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 3


pd rate_limit add_entry send_ban_digest ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 0 md_cmin_win0_32_20_start 0 md_cmin_win0_32_20_end 0xC00 md_cmin_win1_32_20_start 0 md_cmin_win1_32_20_end 0xC00 md_cmin_win2_32_20_start 0 md_cmin_win2_32_20_end 0xC00 md_cmin_win3_32_20_start 0 md_cmin_win3_32_20_end 0xC00 priority 100
pd rate_limit add_entry send_ban_digest ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 1 md_cmin_win0_32_20_start 0 md_cmin_win0_32_20_end 0xC00 md_cmin_win1_32_20_start 0 md_cmin_win1_32_20_end 0xC00 md_cmin_win2_32_20_start 0 md_cmin_win2_32_20_end 0xC00 md_cmin_win3_32_20_start 0 md_cmin_win3_32_20_end 0xC00 priority 100
pd rate_limit add_entry send_ban_digest ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 2 md_cmin_win0_32_20_start 0 md_cmin_win0_32_20_end 0xC00 md_cmin_win1_32_20_start 0 md_cmin_win1_32_20_end 0xC00 md_cmin_win2_32_20_start 0 md_cmin_win2_32_20_end 0xC00 md_cmin_win3_32_20_start 0 md_cmin_win3_32_20_end 0xC00 priority 100
pd rate_limit add_entry send_ban_digest ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 3 md_cmin_win0_32_20_start 0 md_cmin_win0_32_20_end 0xC00 md_cmin_win1_32_20_start 0 md_cmin_win1_32_20_end 0xC00 md_cmin_win2_32_20_start 0 md_cmin_win2_32_20_end 0xC00 md_cmin_win3_32_20_start 0 md_cmin_win3_32_20_end 0xC00 priority 100

pd rate_limit add_entry nop ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 0 md_cmin_win0_32_20_start 0 md_cmin_win0_32_20_end 400 md_cmin_win1_32_20_start 0 md_cmin_win1_32_20_end 0xC00 md_cmin_win2_32_20_start 0 md_cmin_win2_32_20_end 0xC00 md_cmin_win3_32_20_start 0 md_cmin_win3_32_20_end 0xC00 priority 10
pd rate_limit add_entry nop ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 1 md_cmin_win0_32_20_start 0 md_cmin_win0_32_20_end 0xC00 md_cmin_win1_32_20_start 0 md_cmin_win1_32_20_end 400 md_cmin_win2_32_20_start 0 md_cmin_win2_32_20_end 0xC00 md_cmin_win3_32_20_start 0 md_cmin_win3_32_20_end 0xC00 priority 10
pd rate_limit add_entry nop ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 2 md_cmin_win0_32_20_start 0 md_cmin_win0_32_20_end 0xC00 md_cmin_win1_32_20_start 0 md_cmin_win1_32_20_end 0xC00 md_cmin_win2_32_20_start 0 md_cmin_win2_32_20_end 400 md_cmin_win3_32_20_start 0 md_cmin_win3_32_20_end 0xC00 priority 10
pd rate_limit add_entry nop ib_bth_valid 1 ipv4_dstAddr 10.0.8.1 md_winId 3 md_cmin_win0_32_20_start 0 md_cmin_win0_32_20_end 0xC00 md_cmin_win1_32_20_start 0 md_cmin_win1_32_20_end 0xC00 md_cmin_win2_32_20_start 0 md_cmin_win2_32_20_end 0xC00 md_cmin_win3_32_20_start 0 md_cmin_win3_32_20_end 400 priority 10

dump_table last_time
dump_table generate_entry_digest_tab
dump_table read_update_cmin_win0_hash0_tab
dump_table read_update_cmin_win1_hash0_tab
dump_table read_update_cmin_win2_hash0_tab
dump_table read_update_cmin_win3_hash0_tab
dump_table read_update_cmin_win0_hash1_tab
dump_table read_update_cmin_win1_hash1_tab
dump_table read_update_cmin_win2_hash1_tab
dump_table read_update_cmin_win3_hash1_tab
dump_table read_update_cmin_win0_hash2_tab
dump_table read_update_cmin_win1_hash2_tab
dump_table read_update_cmin_win2_hash2_tab
dump_table read_update_cmin_win3_hash2_tab
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


