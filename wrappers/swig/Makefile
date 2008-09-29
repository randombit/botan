LANG=-python
LANG_INC=/usr/include/python2.3

CFLAGS=$(shell botan-config --cflags)
LIBS=$(shell botan-config --libs)

CXX = g++ -g
SWIG = swig -Wall

all: _botan.so

_botan.so: base.o pipe.o filter.o botan_wrap.o
	$(CXX) -shared $^ $(LIBS) -o $@

botan_wrap.cpp: botan.swg base.h
	$(SWIG) $(LANG) -c++ -o $@ $<

botan_wrap.o: botan_wrap.cpp
	$(CXX) $(CFLAGS) -I$(LANG_INC) -c $^ -o $@

base.o: base.cpp base.h
	$(CXX) $(CFLAGS) -c $< -o $@

pipe.o: pipe.cpp base.h
	$(CXX) $(CFLAGS) -c $< -o $@

filter.o: filter.cpp base.h
	$(CXX) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o _botan.so botan.py botan.pyc
	rm -f *_wrap.o *_wrap.cpp
