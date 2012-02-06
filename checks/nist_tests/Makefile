
BOTAN_CONFIG=../../build/botan-config-1.10

CC=g++
FLAGS=-g -Os -W -Wall -ansi
LDFLAGS=$(shell $(BOTAN_CONFIG) --libs) -L../.. -lbotan-1.10
CFLAGS=$(shell $(BOTAN_CONFIG) --cflags) -I../../build/include

x509test: x509test.cpp
	$(CC) $(FLAGS) $(CFLAGS) x509test.cpp $(LDFLAGS) -o x509test

clean:
	rm -f x509test
