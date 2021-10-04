APPS = receive_log_udpSocket

LDFLAGS = -libverbs -lpthread #-ldl
CFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: ${APPS}

clean:
	$(foreach fname,${APPS}, rm -f ${fname})

receive_log_udpSocket: clean
	g++ receive_log_udpSocket.cpp $(CFLAGS) $(LDFLAGS) -lpcap -o receive_log_udpSocket

debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: all clean
