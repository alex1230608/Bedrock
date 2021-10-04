import time
import atexit
import pdb
import threading
import sys
import binascii

def unsigned_to_signed(val, bitwidth):
   if val >= 2**(bitwidth-1):
      return val - 2**bitwidth
   else:
      return val

def reverse_endian(num):
   return ((num>>24)&0xff) | ((num>>8)&0xff00) | ((num<<8)&0xff0000) | ((num<<24)&0xff000000)

def pop_tab():
   qpn = 11749
   startAddr_48_32 = 0x7f00
   endAddr_48_32 = 0x7fff
   objId = 6

   for i in range(0, 100):
      start_large_addr_to_grpId_objMask_ms = p4_pd.start_large_addr_to_grpId_objMask_match_spec_t(
         unsigned_to_signed(qpn+i, 24),
         unsigned_to_signed(startAddr_48_32, 16),
         unsigned_to_signed(endAddr_48_32, 16))
      set_start_grpId_objMask_as = p4_pd.set_start_grpId_objMask_action_spec_t(
         unsigned_to_signed(objId+i, 16),
         unsigned_to_signed(0, 16),
         unsigned_to_signed(0, 16))
      p4_pd.start_large_addr_to_grpId_objMask_table_add_with_set_start_grpId_objMask(
         start_large_addr_to_grpId_objMask_ms, 10,
         set_start_grpId_objMask_as)

      end_large_addr_to_grpId_objMask_ms = p4_pd.end_large_addr_to_grpId_objMask_match_spec_t(
         unsigned_to_signed(qpn+i, 24),
         unsigned_to_signed(startAddr_48_32, 16),
         unsigned_to_signed(endAddr_48_32, 16))
      set_end_grpId_objMask_as = p4_pd.set_end_grpId_objMask_action_spec_t(
         unsigned_to_signed(objId+i, 16),
         unsigned_to_signed(1, 16),
         unsigned_to_signed(1, 16))
      p4_pd.end_large_addr_to_grpId_objMask_table_add_with_set_end_grpId_objMask(
         end_large_addr_to_grpId_objMask_ms, 10,
         set_end_grpId_objMask_as)

      for op in [4, 6, 10, 12, 100]:
         rdma_acl_ms = p4_pd.rdma_acl_match_spec_t(
            unsigned_to_signed(objId+i, 16),
            unsigned_to_signed(op, 8))
         p4_pd.rdma_acl_table_add_with_nop(rdma_acl_ms)

pop_tab()

