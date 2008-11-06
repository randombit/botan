# Assumes Botan was compiled with GCC

BOTAN_DIR = ../..

CXX       = g++
CFLAGS    = -O2 -ansi -W -Wall

INCLUDES  = $(shell $(BOTAN_DIR)/botan-17-config --cflags)

LIBS      = $(shell $(BOTAN_DIR)/botan-17-config --libs)
FLAGS     = $(INCLUDES) $(CFLAGS) -I$(BOTAN_DIR)/build/include -L$(BOTAN_DIR)

SRCS=$(wildcard *.cpp)

PROGS=$(patsubst %.cpp,%,$(SRCS))

all: $(PROGS)

clean:
	@rm -f $(PROGS)

%: %.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@

eax_test: eax_test.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -lboost_regex -o $@
