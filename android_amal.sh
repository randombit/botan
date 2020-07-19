#!/usr/bin/env sh

# Script to produce Botan amalgamation for ZRTP project, Android library

# Modules required by ZRTP library
modules="sha2_32,sha2_64,sha1,twofish,aes,skein,hmac,pubkey,curve25519,cfb,ec_group,ecdh,dh,dl_group"

# Location of my ZRTP project
zrtpBaseDir="$HOME/devhome/ZRTPCPP/botancrypto/android"

toolchain=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin

rm -rf android/x86_64
export CXX=$toolchain/x86_64-linux-android21-clang++
./configure.py --minimized-build --amalgamation --with-build-dir=android/x86_64 \
	       --os=android --cc=clang --cpu=x86_64 --enable-modules=${modules}
cp botan_all.* android/x86_64           # make a copy for, maybe for later us
mv botan_all.* $zrtpBaseDir/x86_64      # move generated code to ZRTP project

rm -rf android/armeabi-v7a
export CXX=$toolchain/armv7a-linux-androideabi21-clang++
./configure.py --minimized-build --amalgamation --with-build-dir=android/armeabi-v7a \
	       --os=android --cc=clang --cpu=arm32 --enable-modules=${modules}
cp botan_all.* android/armeabi-v7a
mv botan_all.* $zrtpBaseDir/armeabi-v7a

rm -rf android/arm64-v8a
export CXX=$toolchain/aarch64-linux-android21-clang++
./configure.py --minimized-build --amalgamation --with-build-dir=android/arm64-v8a \
	       --os=android --cc=clang --cpu=arm64 --enable-modules=${modules}
cp botan_all.* android/arm64-v8a
mv botan_all.* $zrtpBaseDir/arm64-v8a

rm -rf android/x86
export CXX=$toolchain/i686-linux-android21-clang++
./configure.py --minimized-build --amalgamation --with-build-dir=android/x86 \
	       --os=android --cc=clang --cpu=x86 --enable-modules=${modules}
cp botan_all.* android/x86
mv botan_all.* $zrtpBaseDir/x86