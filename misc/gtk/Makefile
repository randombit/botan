
LIBS=$(shell botan-config --libs) $(shell pkg-config --libs gtk+-2.0)
IFLAGS=$(shell botan-config --cflags) $(shell pkg-config --cflags gtk+-2.0)

CXX = g++
CXXFLAGS=-Wall -W $(IFLAGS)

dsa: gtk_ui.o dsa.o
	$(CXX) $^ $(LIBS) -o $@

gtk_ui.o: gtk_ui.cpp gtk_ui.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

dsa.o: dsa.cpp gtk_ui.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f dsa *.o
