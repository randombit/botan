
BOTAN_CONFIG=botan-config

CC=g++
FLAGS=-g -Os -W -Wall -ansi
LDFLAGS=$(shell $(BOTAN_CONFIG) --libs)
CFLAGS=$(shell $(BOTAN_CONFIG) --cflags)

x509test: x509test.cpp
	$(CC) $(FLAGS) $(CFLAGS) x509test.cpp $(LDFLAGS) -o x509test

clean:
	rm -f x509test
