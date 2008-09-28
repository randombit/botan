
SRCS=cms_algo.cpp cms_comp.cpp cms_dalg.cpp cms_dec.cpp cms_ealg.cpp cms_enc.cpp
OBJS=cms_algo.o cms_comp.o cms_dalg.o cms_dec.o cms_ealg.o cms_enc.o

libcms.a: $(OBJS)
	ar libcms.a $(OBJS)

%.o: %.cpp
	g++ -I. $(shell botan-config --cflags) -c $? -o $@

clean:
	rm -f *.o
