# Assumes Botan was compiled with GCC

BOTAN_DIR = ../..

CXX       = g++
CFLAGS    = -O2 -ansi -W -Wall

INCLUDES  = `$(BOTAN_DIR)/botan-config --cflags`
LIBS      = `$(BOTAN_DIR)/botan-config --libs`
FLAGS     = $(INCLUDES) $(CFLAGS) -I$(BOTAN_DIR)/build/include -L$(BOTAN_DIR)

PROGS = asn1 base base64 bzip ca decrypt dh dsa_kgen dsa_sign dsa_ver	\
	ecdsa encrypt factor hash hash_fd hasher hasher2 \
	passhash pkcs10 rsa_dec rsa_enc rsa_kgen self_sig stack		\
	x509info xor_ciph

STRIP     = true

all: $(PROGS)

clean:
	@rm -f $(PROGS)

asn1: asn1.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

base: base.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

base64: base64.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

bzip: bzip.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

ca: ca.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

decrypt: decrypt.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

dh: dh.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

dsa_kgen: dsa_kgen.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

dsa_sign: dsa_sign.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

dsa_ver: dsa_ver.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

encrypt: encrypt.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

ecdsa: ecdsa.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

factor: factor.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

hash: hash.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

hash_fd: hash_fd.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

hasher: hasher.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

hasher2: hasher2.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

pass_dec: pass_dec.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

pass_enc: pass_enc.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

passhash: passhash.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

pkcs10: pkcs10.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

rsa_dec: rsa_dec.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

rsa_enc: rsa_enc.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

rsa_kgen: rsa_kgen.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

self_sig: self_sig.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

stack: stack.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

x509info: x509info.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@

xor_ciph: xor_ciph.cpp
	$(CXX) $(FLAGS) $? $(LIBS) -o $@
	@$(STRIP) $@
