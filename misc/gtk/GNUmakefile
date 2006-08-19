
CC = g++

LIBS=$(shell botan-config --libs) $(shell pkg-config --libs gtk+-2.0)
IFLAGS=$(shell botan-config --cflags) $(shell pkg-config --cflags gtk+-2.0)
FLAGS=-Wall -W $(IFLAGS)

SOURCE=$(wildcard *.cpp)
HEADERS=$(wildcard *.h)

OBJS=$(patsubst %.cpp,%.o,$(SOURCE))

APP=dsa

all: $(APP)

$(APP): $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(APP)

%.o: %.cpp $(HEADERS)
	$(CC) $(FLAGS) -c $<

clean:
	rm -f $(APP) $(OBJS)
