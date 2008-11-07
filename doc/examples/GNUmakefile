
# You must modify generated botan-17-config for workspace builds
# (see that file for details), or else install Botan and direct
# this to the installed system version.
BOTAN_CONFIG = ../../build/botan-17-config --prefix=../..

CXX       = g++
CFLAGS    = -O2 -ansi -W -Wall $(shell $(BOTAN_CONFIG) --cflags)
LIBS      = $(shell $(BOTAN_CONFIG) --libs)

SRCS=$(wildcard *.cpp)

PROGS=$(patsubst %.cpp,%,$(SRCS))

all: $(PROGS)

clean:
	@rm -f $(PROGS)

%: %.cpp
	$(CXX) $(CFLAGS) $? $(LIBS) -o $@

eax_test: eax_test.cpp
	$(CXX) $(CFLAGS) $? $(LIBS) -lboost_regex -o $@
