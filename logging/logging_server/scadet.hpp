#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<cmath>        // std::abs
#include<unordered_map>
#include<unordered_set>
#include<utility> // pair

#define LINE_BITS 15
#define SET_BITS 10
#define SET_MASK ((1 << SET_BITS) - 1)
#define NUM_PP 2

struct pair_hash
{
	template <class T1, class T2>
	std::size_t operator () (std::pair<T1, T2> const &pair) const
	{
		std::size_t h1 = std::hash<T1>()(pair.first);
		std::size_t h2 = std::hash<T2>()(pair.second);

		return h1 ^ h2;
	}
};

typedef uint32_t idType_t;
// typedef uint64_t idType_t;

class ClusterGenPerSet {
  private:
	std::unordered_set<uint32_t> tags;  // Cache line tags for each cluster
	std::unordered_set<std::pair<uint32_t, double>, pair_hash> set_tags; // Set of tags (set of list) for different clusters
	const static uint32_t CACHE_ASSOC = 64;
	const static uint32_t INTRA_GROUP_THRESHOLD_US = 640000; // us
	const static uint32_t INTER_GROUP_THRESHOLD_US = 0;    // us
	const static uint32_t INTRA_GROUP_THRESHOLD = INTRA_GROUP_THRESHOLD_US / 64;
	const static uint32_t INTER_GROUP_THRESHOLD = INTER_GROUP_THRESHOLD_US / 64;
	double cluster_mean;
	bool init;
	uint32_t cnt;
	idType_t prevTime;
	uint32_t prevTag;
	std::pair<uint32_t, double> temp_tuple;
	double prev_mean;

	// for collecting attacker's dqpn
	std::unordered_map<uint32_t, uint32_t> dqpns;
	uint32_t prevDqpn;
	int sockfd;
	struct sockaddr_in addr;
	unsigned int addrlen;
  public:
	ClusterGenPerSet() {
		init = 0;
		cnt = 1;
		addrlen = sizeof(addr);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(12347);
		addr.sin_addr.s_addr = inet_addr("10.0.8.1");
	}
	void firstLog(idType_t tstamp, uint32_t tagId, uint32_t dqpn, int sfd) {
		// printf("First log\n");
		prevTime = tstamp;
		cluster_mean = tstamp;
		prevTag = tagId;
		prevDqpn = dqpn;
		sockfd = sfd;
	}
	void process(idType_t tstamp, uint32_t tagId, uint32_t dqpn) { // the only thing different from scadet is using time stamp instead of count
		// printf("process\n");
		idType_t diff = tstamp - prevTime;
		printf("%10u\n", diff);
		if (diff < INTRA_GROUP_THRESHOLD) { // diff can be 0
			tags.insert(prevTag);
			tags.insert(tagId);
			if (dqpns.find(prevDqpn) == dqpns.end())
				dqpns[prevDqpn] = 1;
			else 
				dqpns[prevDqpn] = dqpns[prevDqpn]+1;
			if (dqpns.find(dqpn) == dqpns.end())
				dqpns[dqpn] = 1;
			else 
				dqpns[dqpn] = dqpns[dqpn]+1;
			cluster_mean = cluster_mean + tstamp;
			cnt = cnt + 1;
		}
		if (diff >= INTRA_GROUP_THRESHOLD) {
			cluster_mean = cluster_mean / cnt;
			uint32_t no_of_unique_lines = tags.size();
			// printf("gap, no_of_unique_lines: %u\n", no_of_unique_lines);
			for (uint32_t t : tags) printf("0x%08x ", t<<1);
			// printf("\n");
			if (no_of_unique_lines >= CACHE_ASSOC) {
				if (INTER_GROUP_THRESHOLD == 0) {
					printf("set_tags inserted\n");
					set_tags.insert({no_of_unique_lines, cluster_mean});
					for (auto banned : dqpns) {
						if (banned.second > CACHE_ASSOC / 2) {
							uint32_t ret = htonl(banned.first);
							sendto(sockfd, &ret, 4,
									0, (struct sockaddr*)&addr, addrlen);
						}
					}
				} else if (init == 0) {
					temp_tuple = {no_of_unique_lines, cluster_mean};
					prev_mean = temp_tuple.second;
					init = 1;
				} else {
					if (std::abs(cluster_mean - prev_mean) <= INTER_GROUP_THRESHOLD) {
						prev_mean = cluster_mean;
						set_tags.insert(temp_tuple);
						set_tags.insert({no_of_unique_lines, cluster_mean});
					}
					temp_tuple = {no_of_unique_lines, cluster_mean};
				}
			}
			cluster_mean = tstamp;
			tags.clear();
			dqpns.clear();
			cnt = 1;
		}
		if (set_tags.size() > NUM_PP) {
			for (auto cluster : set_tags) {
				printf("(%u, %lf) ", cluster.first, cluster.second);
			}
			printf("\n");
		}
		prevTime = tstamp;
		prevTag = tagId;
	}
};

uint32_t va2setId(uint64_t virtAddr) {
	return (virtAddr >> LINE_BITS) & SET_MASK;
}

uint32_t va2tagId(uint64_t virtAddr) {
	return virtAddr >> (SET_BITS + LINE_BITS);
}

std::unordered_map<uint32_t, ClusterGenPerSet> clusterGens;

void processLog(uint32_t tstamp, uint32_t opCode, uint32_t dqpn, uint64_t virtAddr, int sockfd) {
	if (opCode == 12) {
		uint32_t setId = va2setId(virtAddr);
		uint32_t tagId = va2tagId(virtAddr);
		if (clusterGens.find(setId) == clusterGens.end()) {
			clusterGens[setId];
			clusterGens[setId].firstLog(tstamp, tagId, dqpn, sockfd);
		} else {
			clusterGens[setId].process(tstamp, tagId, dqpn);
		}
	}
}

