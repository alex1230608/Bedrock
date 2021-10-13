APPS = spoofv2 client_attacker client_auth server_auth

LDFLAGS = -libverbs -lpthread #-ldl
CFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: ${APPS}

clean:
	$(foreach fname,${APPS}, rm -f ${fname})

spoofv2: clean
	g++ spoofv2.cpp --std=c++11 -lz -o spoofv2

server_auth: clean
	g++ server_auth.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o server_auth

client_auth: clean
	g++ client_auth.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client_auth

client_attacker: clean
	g++ client_attacker.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client_attacker

debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: all clean
