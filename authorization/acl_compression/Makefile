APPS = spoofv1 spoofv2 server client client_attacker client_attacker9 client_acl client_aclMW client_aclMR server_acl server_aclMW server_aclMR receive_log receive_log_udpSocket send_log_udpSocket

LDFLAGS = -libverbs -lpthread #-ldl
CFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: ${APPS}

spoofv2: clean
	g++ spoofv2.cpp --std=c++11 -lz -o spoofv2
spoofv1: clean
	g++ spoofv1.cpp --std=c++11 -lz -o spoofv1
clean:
	$(foreach fname,${APPS}, rm -f ${fname})

server: clean
	g++ server.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o server

server_acl: clean
	g++ server_acl.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o server_acl

server_aclMW: clean
	g++ server_aclMW.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o server_aclMW

server_aclMR: clean
	g++ -g server_aclMR.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o server_aclMR

client: clean
	g++ client.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client
	# -I/usr/src/linux-headers-4.18.0-041800-generic/include/

client_acl: clean
	g++ client_acl.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client_acl

client_aclMW: clean
	g++ client_aclMW.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client_aclMW

client_aclMR: clean
	g++ client_aclMR.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client_aclMR

client_attacker: clean
	g++ client_attacker.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client_attacker

client_attacker9: clean
	g++ client_attacker9.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client_attacker9

receive_log: clean
	g++ receive_log.cpp $(CFLAGS) $(LDFLAGS) -lpcap -o receive_log

receive_log_udpSocket: clean
	g++ receive_log_udpSocket.cpp $(CFLAGS) $(LDFLAGS) -lpcap -o receive_log_udpSocket

send_log_udpSocket: clean
	g++ send_log_udpSocket.cpp $(CFLAGS) $(LDFLAGS) -lpcap -o send_log_udpSocket

debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: all clean
