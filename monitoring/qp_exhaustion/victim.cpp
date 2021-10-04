/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a victim service for resource exhaustion attack.
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

std::vector<VerbsEP *> connections;

cxxopts::ParseResult
parse(int argc, char* argv[])
{
    cxxopts::Options options(argv[0], "Server for the microbenchmark");
    options
      .positional_help("[optional args]")
      .show_positional_help();
 
  try
  {
 
    options.add_options()
      ("a,address", "IP address", cxxopts::value<std::string>(), "IP")
      ("p,port", "port", cxxopts::value<int>(), "port")
      ("help", "Print help")
     ;
 
    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (result.count("address") == 0 || result.count("port") == 0)
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



int main(int argc, char* argv[]){
  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>(); // "192.168.1.20"; .c_str()
  int port = allparams["port"].as<int>();

  ServerRDMA * server = new ServerRDMA(const_cast<char*>(ip.c_str()),port);
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
  conn_param.initiator_depth = 0;
  conn_param.retry_count = 3; // TODO
  conn_param.rnr_retry_count = 3; // TODO 


  struct ibv_pd *pd = server->create_pd();
 
  connections.push_back(server->acceptEP(&attr,&conn_param,pd));

  struct ibv_device_attr dev_attr;
  ibv_query_device(connections[0]->qp->context, &dev_attr);
  printf("Max QP: %d\n", dev_attr.max_qp);

  attr.cap.max_recv_wr = 1;
  attr.send_cq = connections[0]->qp->send_cq;
  attr.recv_cq = connections[0]->qp->recv_cq;
 
  while (true) {
    VerbsEP *ep = server->acceptEP(&attr,&conn_param,pd);
    if (ep != NULL) {
      connections.push_back(ep);
      printf ("Current number of qps: %lu\n", connections.size());
    } else {
      printf("Accept fail\n");
    }
  }

  return 0;
}

