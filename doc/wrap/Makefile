CXX = g++
LANG_FLAGS = -fPIC -Wall -W -ftemplate-depth-255
OPT_FLAGS = -g -Os

PYTHON_ROOT = /usr/lib/python2.3/config
PYTHON_INC = -I/usr/include/python2.3
PYTHON_DEF = -DBOOST_PYTHON_DYNAMIC_LIB -DBOOST_PYTHON_SOURCE
BOOST_ROOT = /usr/local/src/boost

WRAPPER_CFLAGS = $(shell botan-config --cflags)
SHARED_CFLAGS = $(LANG_FLAGS) $(OPT_FLAGS) $(PYTHON_INC)

BOOST_CFLAGS = $(PYTHON_DEF) $(SHARED_CFLAGS)

WRAP_SRC = $(wildcard src/*)
WRAP_OBJS = $(patsubst src/%.cpp,build/botan/%.o,$(WRAP_SRC))

all: botan/_botan.so

include boost.deps

build/libboost_python.so: $(BOOST_OBJS)
	$(CXX) -fPIC -shared -o $@ $(BOOST_DEF) -L$(PYTHON_ROOT) $(PYTHON_INC) -Wl,-soname,libboost_python.so $^

build/botan/%.o: src/%.cpp
	$(CXX) $(SHARED_CFLAGS) $(WRAPPER_CFLAGS) -c $< -o $@

botan/_botan.so: $(WRAP_OBJS) build/libboost_python.so
	$(CXX) -shared -o $@ $(shell botan-config --libs) -L$(PYTHON_ROOT) $(WRAP_OBJS) -Lbuild/ -lboost_python -Wl,-rpath-link,. -Wl,-soname,$@

dirs:
	mkdir -p build build/boost build/botan botan

clean:
	rm -rf build/
	rm -f botan/*.so botan/*.pyc
