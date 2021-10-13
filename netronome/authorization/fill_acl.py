import sys
import random
from collections import Counter
import argparse
import os
fo = open("acl.p4cfg", "w")
sqpn = 23190
string3 = """
{
    "tables": {
        "rdma_acl": {
            "rules": [
"""
for index in range (0,100):
    for op in [4, 6, 10, 12, 100]:
        string3 += '''                {
                    "action": {
                        "type": "nop"
                    },
                    "name": " ''' +str(index)+"_"+str(op)+ '''",
                    "match": {
                        "md.objId": {
                            "value": "'''+str(index+6)+'''"
                        },
                        "ib_bth.opCode": {
                            "value": "''' +str(op) + '''"
                        }
                    }
                },
'''
string3 = string3[:-2] + "\n"
string3 += '''            ],
            "default_rule": {
                "action": {
                    "type": "_drop"
                },
                "name": "0"
            }
        },
        "set_objId2_tab": {
            "default_rule": {
                "action": {
                    "type": "set_objId2"
                },
                "name": "0"
            }
        },
        "cal_rdma_end": {
            "default_rule": {
                "action": {
                    "type": "cal_rdma_end_action"
                },
                "name": "1"
            }
        },
        "start_medium_addr_to_grpId_objMask": {
            "default_rule": {
                "action": {
                    "type": "nop"
                },
                "name": "0"
            }
        },
        "split_endAddr_tab": {
            "default_rule": {
                "action": {
                    "type": "split_endAddr"
                },
                "name": "0"
            }
        },
        "set_objId3_tab": {
            "default_rule": {
                "action": {
                    "type": "set_objId3"
                },
                "name": "0"
            }
        },
        "split_startAddr_tab": {
            "default_rule": {
                "action": {
                    "type": "split_startAddr"
                },
                "name": "0"
            }
        },
        "end_medium_addr_to_grpId_objMask": {
            "default_rule": {
                "action": {
                    "type": "nop"
                },
                "name": "0"
            }
        },
        "start_large_addr_to_grpId_objMask": {
            "rules": [
'''
for i in range (0,100):
    string3 += '''                {
                    "action": {
                        "data": {
                            "start_priority1": {
                                "value": "''' + str(6+i) + '''"
                            },
                            "start_priority2": {
                                "value": "0"
                            },
                            "start_priority3": {
                                "value": "0"
                            }
                        },
                        "type": "set_start_grpId_objMask"
                    },
                    "name": "'''+str(i+1)+'''",
                    "match": {
                        "ib_bth.dqpn" : {
                            "value": "''' + str(sqpn+i) + '''"
                        },
                        "md.startAddr_48_32": {
                            "value": "32512->32767"
                        }
                    }
                },
'''
string3 = string3[:-2] + "\n"

string3 += '''            ],
            "default_rule": {
                "action": {
                    "type": "nop"
                },
                "name": "0"
            }
        },
        "start_singlePage_addr_to_grpId_objMask": {
            "default_rule": {
                "action": {
                    "type": "nop"
                },
                "name": "0"
            }
        },
        "end_singlePage_addr_to_grpId_objMask": {
            "default_rule": {
                "action": {
                    "type": "nop"
                },
                "name": "0"
            }
        },
        "end_small_addr_to_grpId_objMask": {
            "default_rule": {
                "action": {
                    "type": "nop"
                },
                "name": "0"
            }
        },
        "forward": {
            "rules": [
                {
                    "action": {
                        "data": {
                            "egress_spec": {
                                "value": "p0"
                            }
                        },
                        "type": "set_egr"
                    },
                    "name": "forward1",
                    "match": {
                        "ipv4.dstAddr": {
                            "value": "10.0.4.4"
                        },
                        "ipv4": {
                            "value": "valid"
                        }
                    }
                },
                {
                    "action": {
                        "data": {
                            "egress_spec": {
                                "value": "p3"
                            }
                        },
                        "type": "set_egr"
                    },
                    "name": "forward2",
                    "match": {
                        "ipv4.dstAddr": {
                            "value": "10.0.4.9"
                        },
                        "ipv4": {
                            "value": "valid"
                        }
                    }
                },
                {
                    "action": {
                        "data": {
                            "egress_spec": {
                                "value": "p1"
                            }
                        },
                        "type": "set_egr"
                    },
                    "name": "forward3",
                    "match": {
                        "ipv4.dstAddr": {
                            "value": "10.0.4.1"
                        },
                        "ipv4": {
                            "value": "valid"
                        }
                    }
                },
                {
                    "action": {
                        "data": {
                            "egress_spec": {
                                "value": "p2"
                            }
                        },
                        "type": "set_egr"
                    },
                    "name": "forward4",
                    "match": {
                        "ipv4.dstAddr": {
                            "value": "10.0.4.2"
                        },
                        "ipv4": {
                            "value": "valid"
                        }
                    }
                }
            ],
            "default_rule": {
                "action": {
                    "data": {
                        "grp": {
                            "value": "mg1"
                        }
                    },
                    "type": "set_mc"
                },
                "name": "default"
            }
        },
        "start_small_addr_to_grpId_objMask": {
            "default_rule": {
                "action": {
                    "type": "nop"
                },
                "name": "0"
            }
        },
        "end_large_addr_to_grpId_objMask": {
            "rules": [
'''
for i in range(0,100):
    string3 += '''                {
                    "action": {
                        "data": {
                            "end_priority3": {
                                "value": "1"
                            },
                            "end_priority2": {
                                "value": "1"
                            },
                            "end_priority1": {
                                "value": "'''+str(6+i)+'''"
                            }
                        },
                        "type": "set_end_grpId_objMask"
                    },
                    "name": "'''+str(i+1)+'''",
                    "match": {
                        "ib_bth.dqpn" : {
                            "value": "''' + str(sqpn+i) + '''"
                        },
                        "md.endAddr_48_32": {
                            "value": "32512->32767"
                        }
                    }
                },
'''

string3 = string3[:-2] + "\n"

string3 += '''            ],
            "default_rule": {
                "action": {
                    "type": "nop"
                },
                "name": "0"
            }
        },
        "set_objId1_tab": {
            "default_rule": {
                "action": {
                    "type": "set_objId1"
                },
                "name": "0"
            }
        },
        "to_48bit_rdma_len": {
            "default_rule": {
                "action": {
                    "type": "copy_len"
                },
                "name": "1"
            }
        }
    },
    "multicast": {
        "mg1": {
            "group_id": 1,
            "ports": [
                "0",
                "3",
                "1",
                "2"
            ]
        }
    }
}
'''
fo.write(string3)
fo.close()
