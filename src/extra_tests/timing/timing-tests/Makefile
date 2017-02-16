CC=g++
BOTAN_DIR=../../../../
LDIR=$(BOTAN_DIR)
IDIR=$(BOTAN_DIR)build/include
DBG_FLAGS=-g -O3
LIBS=-lbotan-2

CPPFLAGS=$(DBG_FLAGS) -std=c++11 -I$(IDIR) -L$(LDIR) -Wl,-R$(LDIR) '-Wl,-R$$ORIGIN'
LDFLAGS=$(DBG_FLAGS) -I$(IDIR) -L$(LDIR) -Wl,-R$(LDIR) '-Wl,-R$$ORIGIN' $(LIBS)

SOURCES = $(shell find . -maxdepth 1 -name "*.cpp")
HEADERS = $(shell find . -maxdepth 1 -name "*.h")
OBJECTS = $(SOURCES:%.cpp=%.o)
BINARY = main

all: ${BINARY}

${BINARY}: $(OBJECTS) $(HEADERS)
	${CC} $(LDFLAGS) -o ${BINARY} $(OBJECTS) $(LIBS)

# rebuild objects if headers changed
$(OBJECTS): $(HEADERS)

clean:
	rm -f ${BINARY} $(OBJECTS)
