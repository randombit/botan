#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

MAKE_PREFIX=()
TEST_PREFIX=()
TEST_EXE=./botan-test
TEST_FLAGS=()
CFG_FLAGS=(--prefix=/tmp/botan-installation --cc=$CC --os=$TRAVIS_OS_NAME)

# PKCS11 is optional but doesn't pull in new dependencies
CFG_FLAGS+=(--with-pkcs11)

CC_BIN=$CXX

if [ "$BUILD_MODE" = "static" ] || [ "$BUILD_MODE" = "mini-static" ]; then
    CFG_FLAGS+=(--disable-shared --amalgamation)
elif [ "$BUILD_MODE" = "shared" ] || [ "$BUILD_MODE" = "mini-shared" ]; then
    # No special flags required for shared lib build
    CFG_FLAGS+=()
elif [ "$BUILD_MODE" = "bsi" ]; then
    CFG_FLAGS+=(--module-policy=bsi)
elif [ "$BUILD_MODE" = "sonarqube" ]; then
    # No special flags required
    CFG_FLAGS+=()
elif [ "$BUILD_MODE" = "parallel" ]; then

    if [ "$CC" = "gcc" ]; then
        CFG_FLAGS+=(--with-cilkplus)
    else
        CFG_FLAGS+=(--with-openmp)
    fi

elif [ "$BUILD_MODE" = "coverage" ]; then
    CFG_FLAGS+=(--with-coverage --no-optimizations)
elif [ "$BUILD_MODE" = "sanitizer" ]; then
    export ASAN_OPTIONS=detect_leaks=0
    CFG_FLAGS+=(--with-sanitizers --disable-modules=locking_allocator)
elif [ "$BUILD_MODE" = "valgrind" ]; then
    CFG_FLAGS+=(--with-valgrind --with-debug-info --disable-modules=locking_allocator)
    TEST_PREFIX=(valgrind --error-exitcode=9 -v)
fi

if [ "$BUILD_MODE" = "mini-static" ] || [ "$BUILD_MODE" = "mini-shared" ]; then
    CFG_FLAGS+=(--minimized-build --enable-modules="base,dev_random,system_rng,sha2_32,sha2_64,aes")
elif [ "$BUILD_MODE" = "valgrind" ]; then
    # Valgrind on Travis on full build takes too long and the job is killed
    # Prune to the most important stuff
    CFG_FLAGS+=(--module-policy=modern --enable-modules=tls)

elif [ "${BUILD_MODE:0:5}" != "cross" ]; then
    # Only use external libraries when compiling natively
    CFG_FLAGS+=(--with-bzip2 --with-lzma --with-sqlite --with-zlib)

    if [ "$BUILD_MODE" = "coverage" ]; then
        CFG_FLAGS+=(--with-tpm)
        TEST_FLAGS=(--run-online-tests --pkcs11-lib=/tmp/softhsm/lib/softhsm/libsofthsm2.so)
    fi

    # Avoid OpenSSL when using dynamic checkers, or on OS X where it sporadically
    # is not installed on the CI image
    if [ "$TRAVIS_OS_NAME" != "osx" ] && [ "$BUILD_MODE" != "sanitizer" ] && [ "$BUILD_MODE" != "valgrind" ]; then
        CFG_FLAGS+=(--with-openssl)
    fi
fi

if [ "$TRAVIS_OS_NAME" = "osx" ] && [ "${BUILD_MODE:0:5}" != "cross" ]; then
    # The Boost-specific codepaths are tested via the OS X CI
    CFG_FLAGS+=(--with-boost)
fi

if [ "${BUILD_MODE:0:6}" = "cross-" ]; then

    if [ "$TRAVIS_OS_NAME" = "osx" ]; then
        CFG_FLAGS+=(--disable-shared)
        MAKE_PREFIX=(xcrun --sdk iphoneos)
        if [ "$BUILD_MODE" = "cross-arm32" ]; then
            CFG_FLAGS+=(--cpu=armv7 --cc-abi-flags="-arch armv7 -arch armv7s -stdlib=libc++")
        elif [ "$BUILD_MODE" = "cross-arm64" ]; then
            CFG_FLAGS+=(--cpu=armv8-a --cc-abi-flags="-arch arm64 -stdlib=libc++")
        fi
    elif [ "$TRAVIS_OS_NAME" = "linux" ]; then
        CFG_FLAGS+=(--disable-modules=ffi)

        if [ "$BUILD_MODE" = "cross-arm32" ]; then
            CC_BIN=arm-linux-gnueabihf-g++-4.8
            TEST_PREFIX=(qemu-arm -L /usr/arm-linux-gnueabihf/)
            CFG_FLAGS+=(--cpu=armv7)
            CFG_FLAGS+=(--module-policy=modern --enable-modules=tls)
        elif [ "$BUILD_MODE" = "cross-arm64" ]; then
            CC_BIN=aarch64-linux-gnu-g++-4.8
            TEST_PREFIX=(qemu-aarch64 -L /usr/aarch64-linux-gnu/)
            CFG_FLAGS+=(--cpu=armv8-a)
            CFG_FLAGS+=(--module-policy=modern --enable-modules=tls)
        elif [ "$BUILD_MODE" = "cross-ppc32" ]; then
            CC_BIN=powerpc-linux-gnu-g++-4.8
            TEST_PREFIX=(qemu-ppc -L /usr/powerpc-linux-gnu/)
            CFG_FLAGS+=(--cpu=ppc32)
            CFG_FLAGS+=(--module-policy=modern --enable-modules=tls)
        elif [ "$BUILD_MODE" = "cross-ppc64" ]; then
            CC_BIN=powerpc64le-linux-gnu-g++-4.8
            TEST_PREFIX=(qemu-ppc64le -L /usr/powerpc64le-linux-gnu/)
            CFG_FLAGS+=(--cpu=ppc64 --with-endian=little)
            CFG_FLAGS+=(--module-policy=modern --enable-modules=tls)
        elif [ "$BUILD_MODE" = "cross-win32" ]; then
            CC_BIN=i686-w64-mingw32-g++
            # No test prefix needed, PE executes as usual with Wine installed
            CFG_FLAGS+=(--cpu=x86_32 --os=mingw --cc-abi-flags="-static" --disable-shared)
            TEST_EXE=./botan-test.exe
        fi
    fi
fi

CFG_FLAGS+=(--cc-bin="ccache $CC_BIN")

if [ "$BUILD_MODE" = "sonarqube" ]; then
   MAKE_PREFIX=(./build-wrapper-linux-x86/build-wrapper-linux-x86-64 --out-dir bw-outputs)
fi

# configure
./configure.py "${CFG_FLAGS[@]}"

# pre-build ccache stats
ccache --show-stats

# build!

if [ "$BUILD_MODE" = "docs" ]; then
    doxygen build/botan.doxy
    sphinx-build -a -W -c src/build-data/sphinx doc/manual manual-out
else
    MAKE_CMD=("${MAKE_PREFIX[@]}" make -j "$BUILD_JOBS")
    echo "Running" "${MAKE_CMD[@]}"
    time "${MAKE_CMD[@]}"
fi

# post-build ccache stats
ccache --show-stats

# Run SonarQube analysis

if [ "$BUILD_MODE" = "sonarqube" ]; then

    cp src/build-data/sonar-project.properties .

    if [ "$TRAVIS_BRANCH" = "master" ] && [ "$TRAVIS_PULL_REQUEST" = "false" ]; then
       # => This will run a full analysis of the project and push results to the SonarQube server.
       #
       # Analysis is done only on master so that build of branches don't push analyses to the same project and therefore "pollute" the results
       echo "Starting analysis by SonarQube..."
       sonar-scanner "-Dsonar.login=$SONAR_TOKEN"

    # PR analysis deactivated at least until custom quality profiles can be created
    elif false && [ "$TRAVIS_PULL_REQUEST" != "false" ] && [ -n "${GITHUB_TOKEN-}" ]; then
        # => This will analyse the PR and display found issues as comments in the PR, but it won't push results to the SonarQube server
        #
        # For security reasons environment variables are not available on the pull requests
        # coming from outside repositories
        # http://docs.travis-ci.com/user/pull-requests/#Security-Restrictions-when-testing-Pull-Requests
        # That's why the analysis does not need to be executed if the variable GITHUB_TOKEN is not defined.
        echo "Starting Pull Request analysis by SonarQube..."
        sonar-scanner -Dsonar.login="$SONAR_TOKEN" \
                      -Dsonar.analysis.mode=preview \
                      -Dsonar.github.oauth="$GITHUB_TOKEN" \
                      -Dsonar.github.repository="$TRAVIS_REPO_SLUG" \
                      -Dsonar.github.pullRequest="$TRAVIS_PULL_REQUEST"
    fi
       # When neither on master branch nor on a non-external pull request => nothing to do
    fi

if [ "$BUILD_MODE" = "sonarqube" ] || [ "$BUILD_MODE" = "docs" ] || \
       ( [ "${BUILD_MODE:0:5}" = "cross" ] && [ "$TRAVIS_OS_NAME" = "osx" ] ); then
    echo "Running tests disabled on this build type"
else
    TEST_CMD=("${TEST_PREFIX[@]}" $TEST_EXE "${TEST_FLAGS[@]}")
    echo "Running" "${TEST_CMD[@]}"
    time "${TEST_CMD[@]}"
fi

# Run Python tests (need shared libs)
if [ "$BUILD_MODE" = "shared" ]
then
    # TODO: find all things in PATH that begin with python- and execute them :)
    for py in python2 python3
    do
        $py --version
        LD_LIBRARY_PATH=. $py src/python/botan.py
    done
fi

if [ "$BUILD_MODE" != "docs" ]; then
    # Test make install
    make install
fi
