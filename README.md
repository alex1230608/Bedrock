# Bedrock: Programmable Network Support for Secure RDMA Systems

## Overview

Bedrock develops a security foundation for RDMA inside the network, leveraging
programmable data planes in modern network hardware. It designs a range of
defense primitives, including source authentication, access control, as well as
monitoring and logging, to address RDMA-based attacks. 

This repo contains implementation to illustrate all the components mentioned in
our paper. This includes both the addressed attacks and our defenses on
authentication, access control, monitoring and logging. For each case, we
provides implementation of RDMA server, RDMA client, attacker, and Bedrock's
implementation for both programmable switches and SmartNIC.

## Reference implementations

Some of the implementation used in this repo is based on existing open-source
project, including [redmark](https://github.com/spcl/redmark.git),
[Pythia](https://github.com/WukLab/Pythia.git), [SCADET](https://github.com/sabbaghm/SCADET.git),
and some examples codes provided in Tofino switch SDE.

## Environment

### Server

All machines (for RDMA servers, RDMA clients, RDMA attackers) have a six-core
Intel Xeon E5-2643 CPU, 128 GB RAM, 1 TB hard disk, all running an Ubuntu
18.04 OS.

#### Install dependencies for eBPF module

For Bedrock's authentication to work, we need an eBPF module installed on RDMA
servers and clients. The following shows the installation of the dependencies
for this feature.
```
sudo apt-get install bison cmake flex g++ git libelf-dev zlib1g-dev libfl-dev systemtap-sdt-dev binutils-dev
sudo apt-get install llvm-7-dev llvm-7-runtime libclang-7-dev clang-7
sudo apt-get install bison build-essential cmake flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev

git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

### RDMA NIC (RNIC)

All machines are also equipped with Mellanox ConnectX-4 MT27710 25Gbps RNICs
that are configured to use RoCEv2. To install the driver, we follow the
steps described [here](https://community.mellanox.com/s/article/howto-install-mlnx-ofed-driver),
and choose MLNX\_OFED\_LINUX-4.9-2.2.4.0-ubuntu18.04-x86\_64

#### IP Address

The IP addresses of RNICs' interfaces are assumed to be `10.0.8.1`, `10.0.8.2`,
`10.0.8.5`, `10.0.8.6`.

#### Disable iCRC
We get rid of recomputing iCRC by disabling the iCRC check temporarily on our
RNICs.

### Programmable Switch

Our programmable switch is a Wedge 100BF-32X Tofino switch. The SDE version is
8.4.0. Please follow the official documents provided by the vendor to install
it.

### SmartNIC

Our SmartNIC is a Netronome Agilio CX NIC.
Please follow the official documents provided by the vendor to install it.

## Experiments

The following shows how to run experiments to demonstrate the attack scenario
and the Bedrock's defenses on each aspect. We only explain switch version of
Bedrock in this README.

### Tools needed

For commands on switch, several scripts are used, including `p4_build.sh`,
`run_switchd.sh`, `run_bfshell.sh`, `tools/run_pd_rpc.py`.
These scripts are provided by the vendor. 

### Compilation

Compilation for all `.cpp` programs is done by simple `make`. Compilation for
all `.p4` programs in folder `/switch` is done by the following steps:
```
cd ~/bf-sde-8.4.0
source set_sde.bash
./p4_build.sh /path/to/this/repo/switch/<program_name>.p4
```

### Demo Authentication

On one terminal of RDMA server:
```
cd /path/to/this/repo/authentication
sudo python3 ./ebpf_module.py -s 1
```
On one terminal of RDMA client:
```
cd /path/to/this/repo/authentication
sudo python3 ./ebpf_module.py -s 0
```
On the first terminal of switch:
```
./run_switchd.sh -p bedrock_authentication
```
On the second terminal of switch:
```
./run_bfshell.sh -f /path/to/this/repo/switch/bfshell/setup_bedrock_authentication.cmd
./run_bfshell.sh
```
On the third terminal of switch:
```
cd /path/to/this/repo/switch/run_pd_rpc
~/tools/run_pd_rpc.py -p bedrock_authentication control_bedrock_authentication.py
```
In the interactive interface of bfshell on the second terminal of switch:
```
ucli
mc_mgr create-sess
mc_mgr mgrp-create -s 0x10000002 -d 0 -i 666
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 0 -p 15 -p 48 -p 61
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029a -n 0x40000002
```
In the interactive interface of bfshell on the first terminal of switch:
```
ucli
pm
port-add -/- 25G NONE
port-enb -/-
```
On the RDMA server (10.0.8.1):
```
cd /path/to/this/repo/authentication
./server_auth -a 10.0.8.1 -n 2 -m 1
```
On the RDMA client (10.0.8.2):
```
cd /path/to/this/repo/authentication
./client_auth -a 10.0.8.1 -n 1
```
On another terminal of client server (as attacker this time):
```
cd /path/to/this/repo/authentication
./client_attacker -a 10.0.8.1 <SQPN> <PSN>
```
In the `client_auth` program, input `1` to stdin, and then client can
read, write memory on server. Also, the attacker can use remote address and
rkey to attack.

**You may want to replace switch program `bedrock_authentication` with `baseline`, and skip
ebpf module steps for both server and client to see how the attack works first.
Same for all the experiments below.**

### Demo ACL

On the first terminal of switch:
```
./run_switchd.sh -p bedrock_acl
```
On the second terminal of switch:
```
./run_bfshell.sh -f /path/to/this/repo/switch/bfshell/setup_bedrock_acl.cmd
./run_bfshell.sh
```
In the interactive interface of bfshell on the second terminal of switch:
```
ucli
mc_mgr create-sess
mc_mgr mgrp-create -s 0x10000002 -d 0 -i 666
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 0 -p 15 -p 48 -p 61
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029a -n 0x40000002
```
In the interactive interface of bfshell on the first terminal of switch:
```
ucli
pm
port-add -/- 25G NONE
port-enb -/-
```
On one terminal of RDMA server (10.0.8.1):
```
cd /path/to/this/repo/authorization/attack_demo
./server_acl -a 10.0.8.1 -n 1 -m 1 -M 1000000000 -d 0
```
On one terminal of RDMA client (10.0.8.2):
```
cd /path/to/this/repo/authorization/attack_demo
./client_acl -a 10.0.8.1 -n 1
```
Check the stdout on RDMA server terminal, which shows the server QPN (SQPN).
Use that number to setup ACL by modifying the codes in `control_bedrock_acl.py`.
If you want to check if ACL drops traffic before ACL rule is inserted, run the
client code and use the addr and rkey shown in server at the client terminal.
The completition status should be 12. If you inserted ACL rules accordingly,
the completion status should be 0.

To insert ACL rule, after modifying the QPN and corresponding start and end
addresses, on the third terminal of switch:
```
cd /path/to/this/repo/switch/run_pd_rpc
~/tools/run_pd_rpc.py -p bedrock_acl control_bedrock_acl.py
```

### Demo Monitoring - bandwidth exhaustion

On the first terminal of switch:
```
./run_switchd.sh -p bedrock_monitoring_bw
```
On the second terminal of switch:
```
./run_bfshell.sh -f /path/to/this/repo/switch/bfshell/setup_bedrock_monitoring_bw.cmd
./run_bfshell.sh
```
On the third terminal of switch:
```
cd /path/to/this/repo/switch/run_pd_rpc
~/tools/run_pd_rpc.py -p bedrock_monitoring_bw control_bedrock_monitoring_bw.py
```
In the interactive interface of bfshell on the second terminal of switch:
```
ucli
mc_mgr create-sess
mc_mgr mgrp-create -s 0x10000002 -d 0 -i 666
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 0 -p 15 -p 48 -p 61
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029a -n 0x40000002
```
In the interactive interface of bfshell on the first terminal of switch:
```
ucli
pm
port-add -/- 25G NONE
port-enb -/-
```
On one terminal of RDMA server (10.0.8.1):
```
cd /path/to/this/repo/monitoring/bw_exhaustion
./victim -a 10.0.8.1 --reads 16 -c 3 --len 67108864
```
On the clients/attackers (10.0.8.2, 10.0.8.5, 10.0.8.6):
```
cd /path/to/this/repo/monitoring/bw_exhaustion
./client -a 10.0.8.1 --size 65536 --num 1000000 --write --sleep1 0 --sleep2 150   # client, 10.0.8.2
./client -a 10.0.8.1 --size 65536 --num 1000000 --write --sleep1 1 --sleep2 150   # attacker1, 10.0.8.5
./client -a 10.0.8.1 --size 65536 --num 1000000 --write --sleep1 2 --sleep2 150   # attacker2, 10.0.8.6
```
In the control plane program on the third terminal of switch, type Enter to enable the banning process

### Demo Monitoring - QP exhaustion

At switch, do the same thing as the above bandwidth exhaustion experiment
except that we use `bedrock_monitoring_qp`, `control_bedrock_monitoring_qp.py`,
`setup_bedrock_monitoring_qp.cmd` here.

At server,
```
cd /path/to/this/repo/monitoring/qp_exhaustion
./victim -a 10.0.8.1 -p 1234
```
At attacker,
```
./attacker -a 10.0.8.1 -p 1234
```
*Different machines as the victim may get different results.*

### Demo Logging

On the first terminal of switch:
```
./run_switchd.sh -p bedrock_logging
```
On the second terminal of switch:
```
./run_bfshell.sh -f /path/to/this/repo/switch/bfshell/setup_bedrock_logging.cmd
./run_bfshell.sh
```
In the interactive interface of bfshell on the second terminal of switch:
```
ucli

mc_mgr create-sess
mc_mgr mgrp-create -s 0x10000002 -d 0 -i 666
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 0 -p 15 -p 48 -p 61
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029a -n 0x40000002

mc_mgr mgrp-create -s 0x10000002 -d 0 -i 667
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 61 -p 48
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029b -n 0x40000003

mc_mgr mgrp-create -s 0x10000002 -d 0 -i 668
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 61 -p 0
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029c -n 0x40000004

mc_mgr mgrp-create -s 0x10000002 -d 0 -i 669
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 61 -p 15
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029d -n 0x40000005

mc_mgr mgrp-create -s 0x10000002 -d 0 -i 670
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 48
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029e -n 0x40000006

mc_mgr mgrp-create -s 0x10000002 -d 0 -i 671
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 0
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x2000029f -n 0x40000007

mc_mgr mgrp-create -s 0x10000002 -d 0 -i 672
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 15
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x200002a0 -n 0x40000008

mc_mgr mgrp-create -s 0x10000002 -d 0 -i 673
mc_mgr node-create -s 0x10000002 -d 0 -r 0 -p 61
mc_mgr l1-associate -s 0x10000002 -d 0 -g 0x200002a1 -n 0x40000009
```
On the third terminal of switch:
```
cd /path/to/this/repo/switch/run_pd_rpc
~/tools/run_pd_rpc.py -p bedrock_logging control_bedrock_logging.py
```
In the interactive interface of bfshell on the first terminal of switch:
```
ucli
pm
port-add -/- 25G NONE
port-enb -/-
```
On RDMA server (10.0.8.1):
```
cd /path/to/this/repo/logging/pythia_attack_demo
./server -a 10.0.8.1 -n 2
```
On victim client (10.0.8.5):
```
cd /path/to/this/repo/logging/pythia_attack_demo
./client -a 10.0.8.1 -o 10.0.8.5 -t 0
```
On attacker (10.0.8.2):
```
cd /path/to/this/repo/logging/pythia_attack_demo
./client -a 10.0.8.1 -o 10.0.8.5 -t 1
```
On Logging server (10.0.8.6):
```
cd /path/to/this/repo/logging/logging_server
./receive_log_udpSocket
```
On attacker (10.0.8.2):

The result will be in `/path/to/this/repo/logging/pythia_attack_demo/output/`

## License
MIT License

Copyright (c) 2021 Jiarong Xing, Kuo-Feng Hsu, Yiming Qiu, Ziyang Yang, Hongyi Liu, Ang Chen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
