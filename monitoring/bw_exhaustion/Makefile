APPS =  victim client


LDFLAGS =  -libverbs -lrdmacm 
CFLAGS += -Wall -std=c++11 -I./ -O2

all: ${APPS}

victim: clean
	g++ victim.cpp $(CFLAGS) $(LDFLAGS)   -o victim

client: clean
	g++ client.cpp $(CFLAGS) $(LDFLAGS)   -o client

clean:
	$(foreach fname,${APPS}, rm -f ${fname})


.DELETE_ON_ERROR:
.PHONY: all clean
