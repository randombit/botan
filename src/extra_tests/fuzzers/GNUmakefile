
FUZZERS=$(patsubst jigs/%.cpp,%,$(wildcard jigs/*.cpp))

AFL_SAN_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined
CLANG_SAN_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters

SHARED_FLAGS=-O3 -g -std=c++11 -pthread
LIBFUZZER_FLAGS=-DUSE_LLVM_FUZZER -Illvm-build/build/include $(SHARED_FLAGS) $(CLANG_SAN_FLAGS)
AFL_FLAGS=-Iafl-build/build/include $(SHARED_FLAGS)

LIBFUZZER_LIBS=llvm-build/libbotan-1.11.a libFuzzer.a
AFL_LIBS=afl-build/libbotan-1.11.a

#AFL_CXX=AFL_USE_ASAN=1 afl-g++ -m32
AFL_CXX=afl-clang-fast++
CLANG_CXX=clang++

LIBFUZZER_PROGS=$(patsubst %,bin/llvm_fuzz_%,$(FUZZERS))
AFL_PROGS=$(patsubst %,bin/afl_fuzz_%,$(FUZZERS))

all: afl_progs libfuzzer_progs

afl_progs: $(AFL_PROGS)

libfuzzer_progs: $(LIBFUZZER_PROGS)

bin/llvm_fuzz_%: jigs/%.cpp $(LIBFUZZER_LIBS)
	$(CLANG_CXX) $(LIBFUZZER_FLAGS) -DUSE_LLVM_FUZZER $< $(LIBFUZZER_LIBS) -o $@

bin/afl_fuzz_%: jigs/%.cpp $(AFL_LIBS)
	$(AFL_CXX) $(AFL_FLAGS) $< $(AFL_LIBS) -o $@

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

libFuzzer.a: libFuzzer
	cd libFuzzer && clang -c -g -O2 -std=c++11 *.cpp
	ar cr libFuzzer.a libFuzzer/*.o

update:
	svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer libFuzzer
