APPS = client_acl server_acl

LDFLAGS = -libverbs -lpthread #-ldl
CFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: ${APPS}

clean:
	$(foreach fname,${APPS}, rm -f ${fname})

server_acl: clean
	g++ -g server_acl.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o server_acl

client_acl: clean
	g++ client_acl.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o client_acl

debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: all clean
