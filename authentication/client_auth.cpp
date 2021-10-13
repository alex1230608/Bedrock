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
      ("n,num_conn", "Number of connections", cxxopts::value<int>(), "num_conn")
      ("help", "Print help")
     ;
 
    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (result.count("address") == 0 || result.count("num_conn") == 0)
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

 
void printQP(struct ibv_qp *qp) {
	uint32_t *raw = (uint32_t*)qp;
	printf("ibv_qp content:\n");
	for (uint32_t i = 0; i < sizeof(struct ibv_qp)/4; i++) {
		printf("%08x ", raw[i]);
	}
	printf("\nibv_context content:\n");
	raw = (uint32_t*)(qp->context);
	for (uint32_t i = 0; i < sizeof(struct ibv_context)/4; i++) {
		printf("%08x ", raw[i]);
	}
	printf("\n");
	printf("qp->context->cmd_fd,async_fd,num_comp_vectors: %d, %d, %d\n",
			qp->context->cmd_fd,
			qp->context->async_fd,
			qp->context->num_comp_vectors);
}
  
void print_data(VerbsEP *ep){

  struct ibv_qp_attr attr;
  struct ibv_qp_init_attr init_attr;
  int ret = ibv_query_qp(ep->qp, &attr, IBV_QP_RQ_PSN | IBV_QP_SQ_PSN | IBV_QP_AV, &init_attr );
  assert(ret==0 && "ibv_query_qp failed");
  printf("PSNs. receive-PSN: %u send-PSN %u \n", attr.rq_psn, attr.sq_psn);
  printf("interface_id, subnet_prefix: %lu, %lu\n", attr.ah_attr.grh.dgid.global.interface_id, attr.ah_attr.grh.dgid.global.subnet_prefix);
  printf("QPN %u \n",ep->qp->qp_num);
  printQP(ep->qp);
}


std::vector<VerbsEP *> connections;

int main(int argc, char* argv[]){

  // struct ib_qp ibqp;
  // printf("ib_qp address: %08x, %08x\n", &ibqp, &(ibqp.qp_num));

  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>();
  int num_conn = allparams["num_conn"].as<int>();

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
  conn_param.retry_count = 3;  
  conn_param.rnr_retry_count = 3;  
  
  struct ibv_pd* pd = NULL;
  struct ibv_qp_attr mod_attr;
  memset(&mod_attr, 0, sizeof(mod_attr));
  mod_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
  int ret;
  for (int i = 0; i < num_conn; i++) {
    connections.push_back(client->connectEP(&attr,&conn_param,pd));
    if ((ret = ibv_modify_qp(connections[i]->qp, &mod_attr, IBV_QP_ACCESS_FLAGS))) {
      printf("Failed to change access flags, error_msg: %s\n", strerror(ret));
    }
  }

  VerbsEP* ep = connections[0]; 
  pd = ep->pd;
  
  char* ptr = (char*)malloc(4096);
  strcpy(ptr, "1234");
  struct ibv_mr * mr = ep->reg_mem(ptr,4096);
  
  int tmp = 0;
  printf("Enter 1 to continue\n");
  do {
    int res = scanf("%d", &tmp);
    if (res != 1) {
      printf("Need one input\n");
      exit(-2);
    }
  } while (tmp != 1);
  printf("Signal server we are ready\n");
  ep->send_signaled(1, (uint64_t)mr->addr, mr->lkey, 16);

  struct ibv_wc wc;
  while( ep->poll_send_completion(&wc) == 0){

  }
  printf("A message is sent. Completion status is %d\n",wc.status);
  printf("Server is ready if completion status is good\n");

  while(true){
    int qp_id, len;
    uint64_t addr;
    uint32_t rkey;
    char rw;
    printf("Input <QP_id> <mem addr> <rkey> <len> <r/w>\n");
    int res = scanf("%d %lu %u %d %c", &qp_id, &addr, &rkey, &len, &rw);
    if (res != 5) {
      printf("Need five inputs\n");
      exit(-2);
    }
    if (rw == 'w') {
      printf("Input content to write: ");
      int res = scanf("%s", ptr);
      if (res != 1) {
        printf("Need one input\n");
        exit(-2);
      }
      connections[qp_id]->write_signaled(1, (uint64_t)mr->addr, mr->lkey, addr, rkey, len);
      struct ibv_wc wc;
      while( connections[qp_id]->poll_send_completion(&wc) == 0){
    
      }
      printf("A message is written. Completion status is %d\n",wc.status);
    } else if (rw == 'r') {
      connections[qp_id]->read_signaled(1, (uint64_t)mr->addr, mr->lkey, addr, rkey, len);
      struct ibv_wc wc;
      while( connections[qp_id]->poll_send_completion(&wc) == 0){
    
      }
      printf("A message is read. Completion status is %d\n",wc.status);
      printf("Content: ");
      for (int i = 0; i < len; i++) {
        printf("%c", ptr[i]);
      }
      printf("\n");
    }
  }
  
  return 0; 
}

 
 
 
