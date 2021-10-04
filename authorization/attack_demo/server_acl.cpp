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
//#include <time.h>

// #define POOL_SIZE 1000000000ULL
// #define CHUNK 100000UL
// #define NUM_CHUNK POOL_SIZE / CHUNK

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
      ("m,num_obj", "Number of objects", cxxopts::value<uint64_t>(), "num_obj")
      ("M,pool_size", "Memory pool size", cxxopts::value<uint64_t>(), "pool_size")
      ("d,dynamic", "Test dynamic ACL", cxxopts::value<int>(), "dynamic")
      // ("c,chunk", "Chunk size", cxxopts::value<int>(), "chunk")
      ("help", "Print help")
     ;
 
    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (result.count("address") == 0 || result.count("num_conn") == 0
		    || result.count("num_obj") == 0
		    || result.count("pool_size") == 0
		    || result.count("dynamic") == 0)
//		    || result.count("chunk") == 0)
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
  char* raw = (char*)mr->addr;
  printf("obj_id: %d, [addr rkey]: %lu %u, content: ", id, (uint64_t)(mr->addr), mr->rkey);
  for (int i = 0; i < 4; i++) {
          printf("%c", raw[i]);
  }
  printf("\n");
}

void write_obj_addr_key_to_file() {
  FILE *fp = fopen("obj_addr_key.txt", "w");
  for (uint32_t i = 0; i < mrs.size(); i++) {
    fprintf(fp, "%lu %u\n", (uint64_t)(mrs[i]->addr), mrs[i]->rkey);
  }
  fclose(fp);
}

int main(int argc, char* argv[]){
  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>(); // "192.168.1.20"; .c_str()
  int num_conn = allparams["num_conn"].as<int>();
  uint64_t num_obj = allparams["num_obj"].as<uint64_t>();
  uint64_t POOL_SIZE = allparams["pool_size"].as<uint64_t>();
  int dynamic = allparams["dynamic"].as<int>();
  // uint64_t CHUNK = allparams["chunk"].as<int>();
  myip = (char*)ip.c_str();

  int port = 9999;

  ServerRDMA * server = new ServerRDMA(const_cast<char*>(ip.c_str()),port);
  struct ibv_qp_init_attr attr;
  struct rdma_conn_param conn_param;
 
 
  memset(&attr, 0, sizeof(attr));
  attr.cap.max_send_wr = 4096; // 1;
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
    // printf("Before access flag setup\n");
    // print_ep(i, connections[i]);
  }

  printf("First phase finished\n");

  for (int i = 0; i < num_conn; i++) {
    VerbsEP *ep = connections[i];
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
  ptr = (char*)malloc(POOL_SIZE);
  memset(ptr,0,POOL_SIZE);
  uint64_t size = POOL_SIZE/num_obj;
  VerbsEP* ep = connections[0];
  // srand(time(NULL));
  for (uint64_t i = 0; i < num_obj; i++) {
    struct ibv_mr * mr = ep->reg_mem(ptr+size*i,size);
    if (!mr) {
      printf("register memory region failed. errmsg: %s\n", strerror(errno));
    }
    print_mr(i, mr);
    mrs.push_back(mr);
  }

  write_obj_addr_key_to_file();

  struct ibv_wc wc;
  // for(uint32_t i = 0; i<16; i++){
  //  ep->post_recv(i,  mr);
  // }
  ep->post_recv(1,  mrs[0]);
  printf("Waiting client to be ready\n");
  while( ep->poll_recv_completion(&wc) == 0) {}
  printf("A message is recv. Completion status is %d\n",wc.status);
  printf("Client is ready. Start status printing loop\n");

  int count = 0;
  if (dynamic) {
    while(true){
      ep->post_recv(1,  mrs[0]);
      while (ep->poll_recv_completion(&wc) == 0) {}
      count++;
      printf("Old rkey: %u, ", mrs[0]->rkey);
      ep->dereg_mem(mrs[0]);
      if (count%2 == 0)
        mrs[0] = ep->reg_mem(ptr,size);
      else if (count%2 == 1)
        mrs[0] = ep->reg_mem_writeOnly(ptr,size);
      // else if (count%3 == 2)
      //   mrs[0] = ep->reg_mem_readOnly(ptr,size);
      if (!mrs[0]) {
        printf("register memory region failed. errmsg: %s\n", strerror(errno));
      }
      printf("New rkey: %u\n", mrs[0]->rkey);
      uint32_t *content = (uint32_t*)(mrs[0]->addr);
      *content = mrs[0]->rkey;
      ep->send_signaled(1, (uint64_t)mrs[0]->addr, mrs[0]->lkey, 4);
      while( ep->poll_send_completion(&wc) == 0) {}
    }
  } else {
    while(true){
      std::this_thread::sleep_for(std::chrono::milliseconds(5000));
      for (int i = 0; i < num_conn; i++) {
        print_ep(i, connections[i]);
      }
      for (uint64_t i = 0; i < num_obj; i++) {
        print_mr(i, mrs[i]);
      }
    }
  }
   

  return 0;
}

