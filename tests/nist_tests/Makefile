
BOTAN_CONFIG=../../build/botan-config-1.11

CC=g++-4.7.0 -std=c++11
FLAGS=-g -Os -W -Wall
LDFLAGS=-L../.. -lbotan-1.11
CFLAGS=-I../../build/include

x509test: x509test.cpp
	$(CC) $(FLAGS) $(CFLAGS) x509test.cpp $(LDFLAGS) -o x509test

clean:
	rm -f x509test
