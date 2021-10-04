/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a server that will receive packets from the attacker.
 *
 * Copyright (c) 2020-2021 ETH-Zurich. All rights reserved.
 * 
 * Author(s): Konstantin Taranov <konstantin.taranov@inf.ethz.ch>
 * 
 */
#include "verbsEP.hpp"
#include "connectRDMA.hpp"
#include "cxxopts.hpp"
#include <vector>
#include <thread>
#include <arpa/inet.h>

std::vector<VerbsEP *> connections;
std::vector<struct ibv_mr *> mrs;
 
cxxopts::ParseResult
parse(int argc, char* argv[])
{
    cxxopts::Options options(argv[0], "Server for the QP test. It accepts connections and is the injection target.");
    options
      .positional_help("[optional args]")
      .show_positional_help();
 
  try
  {
 
    options.add_options()
      ("a,address", "IP address", cxxopts::value<std::string>(), "IP")
      ("n,num_conn", "Number of connections", cxxopts::value<int>(), "num_conn")
      ("m,num_obj", "Number of objects", cxxopts::value<int>(), "num_obj")
      ("help", "Print help")
     ;
 
    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (result.count("address") == 0 || result.count("num_conn") == 0
		    || result.count("num_obj") == 0)
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    return result;

  } catch (const cxxopts::OptionException& e)
  {
    std::cout << "error parsing options: " << e.what() << std::endl;
    std::cout << options.help({""}) << std::endl;
    exit(1);
  }
}


char * myip = NULL;

void print_ep(int id, VerbsEP *ep){
  struct ibv_qp_attr attr;
  struct ibv_qp_init_attr init_attr;
  int ret = ibv_query_qp(ep->qp, &attr, IBV_QP_STATE| IBV_QP_RQ_PSN | IBV_QP_SQ_PSN | IBV_QP_ACCESS_FLAGS, &init_attr );
  if(ret == 0){
   if(attr.qp_state != 3){
     printf("Connection has been broken\n");
     return;
   }
   printf("QP_id: %d, SQPN: %u, PSN: %u, access flags: %d\n", id,ep->qp->qp_num, attr.rq_psn, attr.qp_access_flags);
  }
}

void print_mr(int id, struct ibv_mr *mr){
  printf("obj_id: %d, [addr rkey]: %lu %u, content: ", id, (uint64_t)(mr->addr), mr->rkey);

  uint32_t* toPrint = (uint32_t*)mr->addr;
  for (int i = 0; i < 1024/4; i++) {
          printf("%08x ", toPrint[i]);
  }
  printf("\n");
}



int main(int argc, char* argv[]){
  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>(); // "192.168.1.20"; .c_str()
  int num_conn = allparams["num_conn"].as<int>();
  int num_obj = allparams["num_obj"].as<int>();
  myip = (char*)ip.c_str();

  int port = 9999;

  ServerRDMA * server = new ServerRDMA(const_cast<char*>(ip.c_str()),port);
  struct ibv_qp_init_attr attr;
  struct rdma_conn_param conn_param;
 
 
  memset(&attr, 0, sizeof(attr));
  attr.cap.max_send_wr = 1;
  attr.cap.max_recv_wr = 16;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  attr.cap.max_inline_data = 0;
  attr.qp_type = IBV_QPT_RC;

  memset(&conn_param, 0 , sizeof(conn_param));
  conn_param.responder_resources = 0;
  conn_param.initiator_depth = 0;
  conn_param.retry_count = 3; // TODO
  conn_param.rnr_retry_count = 3; // TODO 
 
  struct ibv_pd *pd = server->create_pd();
  // struct ibv_qp_attr mod_attr;
  // struct ibv_qp_init_attr dummy_init_attr;
  // memset(&mod_attr, 0, sizeof(mod_attr));
  // mod_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
  // mod_attr.qp_access_flags = 0;
  // printf("Targeted access flags: %d\n", mod_attr.qp_access_flags);
  for (int i = 0; i < num_conn; i++) { 
    VerbsEP *ep = server->acceptEP(&attr,&conn_param,pd);
    connections.push_back(ep);
    printf("Before access flag setup\n");
    print_ep(i, connections[i]);

    struct ibv_qp_attr init_attr, rtr_attr, rts_attr;
    struct ibv_qp_init_attr dummy_init_attr;
    int ret;
    memset(&init_attr, 0, sizeof(init_attr));
    memset(&rtr_attr, 0, sizeof(rtr_attr));
    memset(&rts_attr, 0, sizeof(rts_attr));
    if ((ret = ibv_query_qp(ep->qp, &init_attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS, &dummy_init_attr ))) {
            printf("Failed to query init_attr, error_msg: %s\n", strerror(ret));
    } else {
            init_attr.qp_state = IBV_QPS_INIT;
            init_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
            // printf("init_attr: %d, %hu, %u, %08x\n", init_attr.qp_state, init_attr.pkey_index, (uint32_t)init_attr.port_num, init_attr.qp_access_flags);
    }
    if ((ret = ibv_query_qp(ep->qp, &rtr_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER, &dummy_init_attr))) {
            printf("Failed to query rtr_attr, error_msg: %s\n", strerror(ret));
    } else {
            rtr_attr.qp_state = IBV_QPS_RTR;
    }
    if ((ret = ibv_query_qp(ep->qp, &rts_attr, IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC, &dummy_init_attr))) {
            printf("Failed to query rts_attr, error_msg: %s\n", strerror(ret));
    } else {
            rts_attr.qp_state = IBV_QPS_RTS;
    }

    struct ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RESET;

    if ((ret = ibv_modify_qp(ep->qp, &qp_attr, IBV_QP_STATE))) {
            printf("Failed to reset state, ret: %d\n", ret);
    }

    if ((ret = ibv_modify_qp(ep->qp, &init_attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))) {
            printf("Failed to init state, error_msg: %s\n", strerror(ret));
    }

    if ((ret = ibv_modify_qp(ep->qp, &rtr_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER))) {
            printf("Failed to change to RTR, error_msg: %s\n", strerror(ret));
    }

    if ((ret = ibv_modify_qp(ep->qp, &rts_attr, IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))) {
            printf("Failed to change to RTS, error_msg: %s\n", strerror(ret));
    }

//     if ((ret = ibv_query_qp(connections[i]->qp, &mod_attr, IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC | IBV_QP_CUR_STATE | IBV_QP_ACCESS_FLAGS | IBV_QP_MIN_RNR_TIMER | IBV_QP_ALT_PATH | IBV_QP_PATH_MIG_STATE, &dummy_init_attr))) {
//       printf("Failed to query rts attr, error_msg: %s\n", strerror(ret));
//     } else {
//       mod_attr.cur_qp_state = mod_attr.qp_state;
//       if ((ret = ibv_modify_qp(connections[i]->qp, &mod_attr, IBV_QP_CUR_STATE | IBV_QP_ACCESS_FLAGS | IBV_QP_CUR_STATE | IBV_QP_ACCESS_FLAGS | IBV_QP_MIN_RNR_TIMER | IBV_QP_PATH_MIG_STATE))) {
//       // if ((ret = ibv_modify_qp(connections[i]->qp, &mod_attr, IBV_QP_ACCESS_FLAGS))) {
//         printf("Failed to change access flags, error_msg: %s\n", strerror(ret));
//       }
//     }
  }
  for (int i = 0; i < num_conn; i++) {
    print_ep(i, connections[i]);
  }

  char* ptr;
  VerbsEP* ep = connections[0];
  for (int i = 0; i < num_obj; i++) {
    ptr = (char*)malloc(4096);
    memset(ptr,0,4096);
    *(ptr+1024) = 1;
    struct ibv_mr * mr = ep->reg_mem(ptr,4096);
    print_mr(i, mr);
    mrs.push_back(mr);
  }

  struct ibv_wc wc;
  // for(uint32_t i = 0; i<16; i++){
  //  ep->post_recv(i,  mr);
  // }
  ep->post_recv(1,  mrs[0]);
  printf("Waiting client to be ready\n");
  while( ep->poll_recv_completion(&wc) == 0) {}
  printf("A message is recv. Completion status is %d\n",wc.status);
  printf("Client is ready. Start status printing loop\n");

  while(true){
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    for (int i = 0; i < num_conn; i++) {
      print_ep(i, connections[i]);
    }
    for (int i = 0; i < num_obj; i++) {
      print_mr(i, mrs[i]);
    }
  }
   

  return 0;
}

