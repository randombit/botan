
FUZZERS=$(patsubst jigs/%.cpp,%,$(wildcard jigs/*.cpp))

AFL_SAN_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined
CLANG_SAN_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined
#CLANG_SAN_FLAGS=-fsanitize=address

CLANG_COV_FLAGS=-fsanitize-coverage=edge,indirect-calls,8bit-counters
SHARED_FLAGS=-O3 -g -std=c++11 -pthread
CFG_FLAGS=--with-debug-info --unsafe-fuzzer-mode

LIBFUZZER_FLAGS=-Illvm-build/build/include $(SHARED_FLAGS) $(CLANG_COV_FLAGS) $(CLANG_SAN_FLAGS)
AFL_FLAGS=-Iafl-build/build/include $(SHARED_FLAGS) -DINCLUDE_AFL_MAIN

LIBFUZZER_LIBS=llvm-build/libbotan-2.a libFuzzer.a
AFL_LIBS=afl-build/libbotan-2.a

#AFL_CXX=AFL_USE_ASAN=1 afl-g++ -m32
AFL_CXX=afl-g++
AFL_CXX_TYPE=gcc
CLANG_CXX=clang++

LIBFUZZER_PROGS=$(patsubst %,bin/llvm_fuzz_%,$(FUZZERS))
AFL_PROGS=$(patsubst %,bin/afl_fuzz_%,$(FUZZERS))

all:
	@echo "make afl for AFL, llvm for libFuzzer"

afl: dirs afl-build $(AFL_PROGS)

llvm: dirs llvm-build $(LIBFUZZER_PROGS)

bin/llvm_fuzz_%: jigs/%.cpp $(LIBFUZZER_LIBS)
	$(CLANG_CXX) $(LIBFUZZER_FLAGS) $< $(LIBFUZZER_LIBS) -o $@

bin/afl_fuzz_%: jigs/%.cpp $(AFL_LIBS)
	$(AFL_CXX) $(AFL_FLAGS) $< $(AFL_LIBS) -o $@


dirs:
	mkdir -p bin
	mkdir -p output
	mkdir -p corpus

afl-build:
	../../../configure.py $(CFG_FLAGS) --with-build-dir=afl-build --cc=$(AFL_CXX_TYPE) --cc-bin=$(AFL_CXX)
	make -j2 -f afl-build/Makefile afl-build/libbotan-2.a

llvm-build:
	../../../configure.py $(CFG_FLAGS) --with-build-dir=llvm-build --cc=clang --cc-bin=$(CLANG_CXX) --cc-abi-flags="$(CLANG_COV_FLAGS) $(CLANG_SAN_FLAGS)"
	make -j2 -f llvm-build/Makefile llvm-build/libbotan-2.a

# libFuzzer default is max_len 64 this sets 140 but allows override via args=
run_llvm_%: bin/llvm_fuzz_%
	$(eval FUZZER = $(subst bin/llvm_fuzz_,,$<))
	mkdir -p output/$(FUZZER)/llvm/queue
	mkdir -p output/$(FUZZER)/llvm/outputs
	$< -max_len=140 -artifact_prefix=output/$(FUZZER)/llvm/outputs/ output/$(FUZZER)/llvm/queue corpus/$(FUZZER) $(args)

run_afl_%: bin/afl_fuzz_%
	$(eval FUZZER = $(subst bin/afl_fuzz_,,$<))
	mkdir -p output/$(FUZZER)/afl
	afl-fuzz $(args) -o output/$(FUZZER)/afl -i corpus/$(FUZZER) $<

cmin_%: bin/afl_fuzz_%
	$(eval FUZZER = $(subst bin/afl_fuzz_,,$<))
	rm -rf cmin-dir
	mv corpus/$(FUZZER) cmin-dir
	-cp -n output/$(FUZZER)/afl/queue/* cmin-dir
	-cp -n output/$(FUZZER)/llvm/queue/* cmin-dir
	afl-cmin -i cmin-dir -o corpus/$(FUZZER) $<
	rm -rf cmin-dir

clean:
	rm -f $(LIBFUZZER_PROGS) $(AFL_PROGS)

clean_builds: clean
	rm -rf afl-build llvm-build

libFuzzer:
	svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer libFuzzer

libFuzzer.a: libFuzzer
	cd libFuzzer && clang -c -g -O2 -std=c++11 *.cpp
	ar cr libFuzzer.a libFuzzer/*.o

update:
	svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer libFuzzer
