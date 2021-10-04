import time
import atexit
import pdb
import threading
import sys

def clean_thread():
	p4_pd.digest_fields_register()
	print "Cleaning receiver registered, ready to start receiving cleaning requests"
	while True:
	    try:
	        msg = cleaning_req_get()
	        cleaning_req_process(msg)
	    except Exception as e:
	    	print "Req broken: ", e
	        break

	    time.sleep(1/1000.0)

@atexit.register
def cleaning_unregister():
    global digest
    try:
        p4_pd.digest_fields_digest_notify_ack(digest.msg_ptr)
        p4_pd.digest_fields_deregister()
    except:
        pass

def cleaning_req_get():
    global digest
    try:
        digest = p4_pd.digest_fields_get_digest()
    except Exception as e:
        print "Got Exception ", e
        return []
    if digest.msg != []:
        # print "Found digest message"
        # This prevents a crash in learn_unregister, by ensuring that it
        # will not attempt to ack the same msg_ptr twice (DRV-1108)
        msg_ptr = digest.msg_ptr
        digest.msg_ptr = 0
        p4_pd.digest_fields_digest_notify_ack(msg_ptr)
    return digest.msg

def cleaning_req_process(msg):
    if len(msg) > 0:
        print "Size of msg: %d" % (len(msg))
    for m in msg:
        # if m.md_digest_type == 1:
        #     print "WinId: %d, diff: %d" % (m.md_winId, m.md_tstamp_diff)
        #     if m.md_winId != 0 and m.md_winId != 3:
        #         p4_pd.register_reset_all_cmin_win0_hash0()
        #         p4_pd.register_reset_all_cmin_win0_hash1()
        #         p4_pd.register_reset_all_cmin_win0_hash2()
        #     if m.md_winId != 1 and m.md_winId != 0:
        #         p4_pd.register_reset_all_cmin_win1_hash0()
        #         p4_pd.register_reset_all_cmin_win1_hash1()
        #         p4_pd.register_reset_all_cmin_win1_hash2()
        #     if m.md_winId != 2 and m.md_winId != 1:
        #         p4_pd.register_reset_all_cmin_win2_hash0()
        #         p4_pd.register_reset_all_cmin_win2_hash1()
        #         p4_pd.register_reset_all_cmin_win2_hash2()
        #     if m.md_winId != 3 and m.md_winId != 2:
        #         p4_pd.register_reset_all_cmin_win3_hash0()
        #         p4_pd.register_reset_all_cmin_win3_hash1()
        #         p4_pd.register_reset_all_cmin_win3_hash2()
        # elif m.md_digest_type == 2:
        if m.md_digest_type == 2:
            print "Ban dqpn: %d, ip: 0x%s" % (
                m.ctrl_banned_dqpn,
                hex(m.ipv4_dstAddr))
            ban_acl_ms = p4_pd.ban_acl_match_spec_t(1, m.ipv4_dstAddr, m.ctrl_banned_dqpn)
            try:
                p4_pd.ban_acl_table_add_with_drop_exit(ban_acl_ms)
            except Exception as e:
                if e.code != 4:
                    print "ban_acl table op Exception, ", e
                continue;
        else:
            continue

clean_t = threading.Thread(target=clean_thread)

#Sleep to make sure the switch is fully set up before trying to register the digest
print "Sleeping before starting cleaning thread ..."
time.sleep(5)

clean_t.start()
clean_t.join()
