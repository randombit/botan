#!/usr/bin/env sh

# Script to produce Botan amalgamation for ZRTP project, host (Linux x86_64) library

# Modules required by ZRTP library
modules="sha2_32,sha2_64,sha1,twofish,aes,skein,hmac,pubkey,curve25519,cfb,ec_group,ecdh,dh,dl_group"

# Location of my ZRTP project
zrtpBaseDir="$HOME/devhome/ZRTPCPP/botancrypto/x86_64"

./configure.py --minimized-build --cc=clang --amalgamation --with-build-dir=amal_x86_64 --enable-modules=${modules}
cp botan_all.* amal_x86_64
mv botan_all.* $zrtpBaseDir
