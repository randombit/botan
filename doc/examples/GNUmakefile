
BOTAN_CONFIG = botan-config

CXX       = g++
CFLAGS    = -O2 -ansi -std=c++11 -W -Wall -I../../build/include
LIBS      = -L../.. -lbotan-1.11

SRCS=$(wildcard *.cpp)

PROGS=$(patsubst %.cpp,%,$(SRCS))

all: $(PROGS)

clean:
	@rm -f $(PROGS)

%: %.cpp
	$(CXX) $(CFLAGS) $? $(LIBS) -o $@

eax_test: eax_test.cpp
	$(CXX) $(CFLAGS) $? $(LIBS) -lboost_regex -o $@

asio_tls_server: asio_tls_server.cpp credentials.h
	$(CXX) $(CFLAGS) $< $(LIBS) -lboost_thread -lboost_system -o $@
