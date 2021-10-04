// #include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()

// #include<net/ethernet.h>
// #include<netinet/udp.h>
// #include<netinet/ip.h>

// #include <pthread.h>

#include"scadet.hpp"

#define BUFFER_SIZE 2048

struct log{
	uint32_t tstamp;
	uint32_t opCode_dqpn;
	uint32_t virtAddr_h;
	uint32_t virtAddr_l;
};

struct loghdr {
	// bth
	uint8_t opCode;
	uint8_t ignored[3];
	uint32_t dqpn;
	uint32_t psn; // ack (1), reserved(7), psn(24)
	// reth
	uint32_t virtAddr_h;
	uint32_t virtAddr_l;
	uint32_t rkey;
	uint32_t len;
	// logs
	struct log logs[8];
};

// void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
// void *pcapLoopThreadFun(void *vargp); 

// uint64_t count = 0;
// pcap_t *handle; //Handle of the device that shall be sniffed

void printHex(char *buf, int len) {
	len = len > 160 ? 160 : len;
	int i;
	for (i = 0; i+4-1 < len; i += 4) {
		uint32_t x = *(uint32_t*)(buf+i);
		printf("%08x ", x);
		if ((i % 16) == 12)
			printf("\n");
	}
	if (i == len && (i % 16 != 0)) {
		printf("\n");
	}
	for (; i < len; i++) {
		printf("%02x", buf[i]);
		if (i == len-1)
			printf("\n");
	}
}

int main()
{
	int sockfd, recved;
	struct sockaddr_in addr;
	unsigned int addrlen = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(12345);
	addr.sin_addr.s_addr = inet_addr("10.0.8.6");
	char buffer[BUFFER_SIZE];

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0) {
		printf("Socket creation error\n");
		exit(-1);
	}

	printf("Socket created\n");

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		printf("Binding socket failed\n");
		exit(-3);
	}

	printf("Socket bound\n");

	// int disable = 1;
	// if (setsockopt(sockfd, SOL_SOCKET, SO_NO_CHECK, (void*)&disable, sizeof(disable)) < 0) {
	// 	printf("Disabling UDP checksum check fail\n");
	// 	exit(-2);
	// }

	// printf("UDP checksum disabled\n");

	uint64_t count = 0;
	while (1) {
		recved = recvfrom(sockfd, buffer, BUFFER_SIZE,
				0, (struct sockaddr*)&addr, &addrlen);
		if (recved > 0) {
			// struct loghdr *logh = (struct loghdr*)buffer;
			// printHex(buffer, recved);
			// printf("\n");
 			struct loghdr *logh = (struct loghdr*)buffer;
 			if (count % 1 == 0) {
 				// printf("count: %lu\n", count);
 				// // printf("udp: %hu, %hu\n", ntohs(udph->source), ntohs(udph->dest));
 				 //printf("bth: %u, 0x%06x\n", (uint32_t)logh->opCode, ntohl(logh->dqpn));
 				 //printf("reth: %u\n", ntohl(logh->len));
 				for (int i = 0; i < 8; i++) {
					uint32_t tstamp = ntohl(logh->logs[i].tstamp);
					uint32_t opCode = logh->logs[i].opCode_dqpn & 0xFF;
 					uint32_t dqpn = ntohl(logh->logs[i].opCode_dqpn) & 0x00FFFFFF;
 					uint64_t virtAddr = ((uint64_t)ntohl(logh->logs[i].virtAddr_h) << 32) + ntohl(logh->logs[i].virtAddr_l);
 					 printf("%10u, %2u, 0x%06x, 0x%016lx\n", 
 					 		tstamp,
 					 		opCode,
 					 		dqpn,
 					 		virtAddr);
					processLog(tstamp, opCode, dqpn, virtAddr, sockfd);
 				}
 			}
			count++;
		} else {
			printf("Shoudn't happen\n");
		}
	}

	return 0;	
}

// void *pcapLoopThreadFun(void *vargp) 
// {
// 	//Put the device in sniff loop
// 	pcap_loop(handle , -1 , process_packet , NULL);
// 	
// 	return NULL; 
// }
// 
// void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
// {
// 	count++;
// 	struct udphdr *udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
// 	struct loghdr *logh = (struct loghdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
// 	if (count % 1000 == 0) {
// 		printf("count: %lu\n", count);
// 		printf("udp: %hu, %hu\n", ntohs(udph->source), ntohs(udph->dest));
// 		printf("bth: %u, 0x%06x\n", (uint32_t)logh->opCode, ntohl(logh->dqpn));
// 		printf("reth: %u\n", ntohl(logh->len));
// 		for (int i = 0; i < 8; i++) {
// 			uint32_t dqpn = ntohl(logh->logs[i].opCode_dqpn) & 0x00FFFFFF;
// 			uint64_t virtAddr = ((uint64_t)ntohl(logh->logs[i].virtAddr_h) << 32) + ntohl(logh->logs[i].virtAddr_l);
// 			printf("%10u, %2u, 0x%06x, %20lu\n", 
// 					ntohl(logh->logs[i].tstamp),
// 					logh->logs[i].opCode_dqpn & 0xFF,
// 					dqpn,
// 					virtAddr);
// 		}
// 	}
// }
