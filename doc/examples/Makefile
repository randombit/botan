# Assumes Botan was compiled with GCC

BOTAN_DIR = ../..

CXX       = g++
WARNINGS  = -ansi -W -Wall
#CXX       = icc
#WARNINGS  = -w1

INCLUDES  = `$(BOTAN_DIR)/botan-config --cflags`
LIBS      = `$(BOTAN_DIR)/botan-config --libs`
FLAGS     = $(INCLUDES) $(WARNINGS) -I$(BOTAN_DIR)/build/include -L$(BOTAN_DIR)

X509_EX   = ca pkcs10 self_sig x509info asn1
RSA_EX    = rsa_kgen rsa_enc rsa_dec
DSA_EX    = dsa_kgen dsa_sign dsa_ver
DH_EX     = dh
HASH_EX   = hash hash_fd hasher hasher2 stack
MISC_EX   = base base64 bzip encrypt decrypt fips140 xor_ciph

PROGS     = $(X509_EX) $(RSA_EX) $(DSA_EX) $(DH_EX) $(HASH_EX) $(MISC_EX)

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

fips140: fips140.cpp
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
