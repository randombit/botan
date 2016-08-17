#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "static" ]; then
    CFG_FLAGS=(--disable-shared --via-amalgamation)
elif [ "$BUILD_MODE" = "shared" ] || [ "$BUILD_MODE" = "sonarqube" ]; then
    CFG_FLAGS=()
elif [ "$BUILD_MODE" = "coverage" ]; then
    CFG_FLAGS=(--with-coverage)
elif [ "$BUILD_MODE" = "sanitizer" ]; then
    CFG_FLAGS=(--with-sanitizers)
fi

if [ "$MODULES" = "min" ]; then
    CFG_FLAGS+=(--minimized-build --enable-modules=base)
fi

if [ "$BOOST" = "y" ]; then
    CFG_FLAGS+=(--with-boost)
fi

# enable ccache		
if [ "$TRAVIS_OS_NAME" = "linux" ]; then
    ccache --max-size=30M
    ccache --show-stats

    export CXX="ccache $CXX"		
 fi

# configure
if [ "$TARGETOS" = "ios32" ]; then
    ./configure.py "${CFG_FLAGS[@]}" --cpu=armv7 --cc=clang \
        --cc-abi-flags="-arch armv7 -arch armv7s -stdlib=libc++" \
        --prefix=/tmp/botan-installation

elif [ "$TARGETOS" = "ios64" ]; then
    ./configure.py "${CFG_FLAGS[@]}" --cpu=armv8-a --cc=clang \
        --cc-abi-flags="-arch arm64 -stdlib=libc++" \
        --prefix=/tmp/botan-installation

else
    $CXX --version
    ./configure.py "${CFG_FLAGS[@]}" --cc="$CC" --cc-bin="$CXX" \
        --with-bzip2 --with-lzma --with-openssl --with-sqlite --with-zlib \
        --prefix=/tmp/botan-installation
fi

# build
if [ "${TARGETOS:0:3}" = "ios" ]; then
    xcrun --sdk iphoneos make -j 2
elif [ "$BUILD_MODE" = "sonarqube" ]; then
    ./build-wrapper-linux-x86/build-wrapper-linux-x86-64 --out-dir bw-outputs make -j 2
else
    make -j 2
fi

if [ "$MODULES" != "min" ] && [ "${TARGETOS:0:3}" != "ios" ] && [ "$BUILD_MODE" != "sonarqube" ]; then
    ./botan-test
fi

if [ "$MODULES" != "min" ] && [ "$BUILD_MODE" = "shared" ] && [ "$TARGETOS" = "native" ]
then
    python --version
    python3 --version
    LD_LIBRARY_PATH=. python src/python/botan.py
    LD_LIBRARY_PATH=. python3 src/python/botan.py
fi

make install
