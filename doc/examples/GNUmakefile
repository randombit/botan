
BOTAN_CONFIG = botan-config

CXX       = g++-4.5-20091112
CFLAGS    = -O2 -ansi -std=c++0x -W -Wall -I../../build/include
LIBS      = -L../.. -lbotan-1.10

SRCS=$(wildcard *.cpp)

PROGS=$(patsubst %.cpp,%,$(SRCS))

all: $(PROGS)

clean:
	@rm -f $(PROGS)

%: %.cpp
	$(CXX) $(CFLAGS) $? $(LIBS) -o $@

eax_test: eax_test.cpp
	$(CXX) $(CFLAGS) $? $(LIBS) -lboost_regex -o $@
