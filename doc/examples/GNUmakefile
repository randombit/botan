
BOTAN_CONFIG = botan-config

CXX       = g++-4.7.0
CFLAGS    = -O2 -ansi -std=c++0x -W -Wall -I../../build/include
LIBS      = -L../.. -lbotan-1.99

SRCS=$(wildcard *.cpp)

PROGS=$(patsubst %.cpp,%,$(SRCS))

all: $(PROGS)

clean:
	@rm -f $(PROGS)

%: %.cpp
	$(CXX) $(CFLAGS) $? $(LIBS) -o $@

eax_test: eax_test.cpp
	echo $(CXX) $(CFLAGS) $? $(LIBS) -lboost_regex -o $@

asio_tls_server.o: asio_tls_server.cpp
	g++-4.6.0 -c $(CFLAGS) -pthread $? -o $@

asio_tls_server: asio_tls_server.o
	$(CXX) $? $(LIBS) -lboost_thread -lboost_system -lpthread -o $@
