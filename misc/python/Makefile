CXX = g++
LANG_FLAGS = -fPIC -Wall -Wno-unused -ftemplate-depth-255
OPT_FLAGS = -g -Os

PYTHON_ROOT = /usr/lib/python2.4/config
PYTHON_INC = -I/usr/include/python2.4
PYTHON_DEF = -DBOOST_PYTHON_DYNAMIC_LIB -DBOOST_PYTHON_SOURCE

WRAPPER_CFLAGS = $(shell botan-config --cflags)
SHARED_CFLAGS = $(LANG_FLAGS) $(OPT_FLAGS) $(PYTHON_INC)

BOOST_CFLAGS = $(PYTHON_DEF) $(SHARED_CFLAGS)

WRAP_SRC = $(wildcard src/*)
WRAP_OBJS = $(patsubst src/%.cpp,%.o,$(WRAP_SRC))

all: botan/_botan.so

%.o: src/%.cpp
	$(CXX) $(SHARED_CFLAGS) $(WRAPPER_CFLAGS) -c $< -o $@

botan/_botan.so: $(WRAP_OBJS) 
	$(CXX) -shared -o $@ $(shell botan-config --libs) -L$(PYTHON_ROOT) $(WRAP_OBJS) -lboost_python -Wl,-rpath-link,. -Wl,-soname,$@

clean:
	rm -f $(WRAP_OBJS) botan/_botan.so botan/*.pyc
