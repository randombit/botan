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
if [ "$TRAVIS_OS_NAME" = "linux" ] && [ "$BUILD_MODE" != "sonarqube" ]; then
    ccache --max-size=30M
    ccache --show-stats

    export CXX="ccache $CXX"
fi

# configure
if [ "$TARGETOS" = "ios32" ]; then
    ./configure.py "${CFG_FLAGS[@]}" --cpu=armv7 --cc=clang \
        --cc-abi-flags="-arch armv7 -arch armv7s -stdlib=libc++" \
        --with-pkcs11 --prefix=/tmp/botan-installation

elif [ "$TARGETOS" = "ios64" ]; then
    ./configure.py "${CFG_FLAGS[@]}" --cpu=armv8-a --cc=clang \
        --cc-abi-flags="-arch arm64 -stdlib=libc++" \
        --with-pkcs11 --prefix=/tmp/botan-installation

else
    $CXX --version
    ./configure.py "${CFG_FLAGS[@]}" --cc="$CC" --cc-bin="$CXX" \
        --with-bzip2 --with-lzma --with-openssl --with-sqlite --with-zlib \
        --with-pkcs11 --prefix=/tmp/botan-installation
fi

# build
if [ "${TARGETOS:0:3}" = "ios" ]; then
    xcrun --sdk iphoneos make -j 2
elif [ "$BUILD_MODE" = "sonarqube" ]; then
    ./build-wrapper-linux-x86/build-wrapper-linux-x86-64 --out-dir bw-outputs make -j 2
else
    make -j 2
fi

# Run SonarQube analysis
if [ "$TRAVIS_BRANCH" = "master" ] && [ "$TRAVIS_PULL_REQUEST" = "false" ] && [ "$BUILD_MODE" = "sonarqube" ]; then
    # => This will run a full analysis of the project and push results to the SonarQube server.
    #
    # Analysis is done only on master so that build of branches don't push analyses to the same project and therefore "pollute" the results
    echo "Starting analysis by SonarQube..."
    sonar-scanner -Dsonar.login=$SONAR_TOKEN
fi

# PR analysis deactivated at least until custom quality profiles can be created
#elif [ "$TRAVIS_PULL_REQUEST" != "false" ] && [ -n "${GITHUB_TOKEN-}" ]  && [ "$BUILD_MODE" = "sonarqube" ]; then
    # => This will analyse the PR and display found issues as comments in the PR, but it won't push results to the SonarQube server
    #
    # For security reasons environment variables are not available on the pull requests
    # coming from outside repositories
    # http://docs.travis-ci.com/user/pull-requests/#Security-Restrictions-when-testing-Pull-Requests
    # That's why the analysis does not need to be executed if the variable GITHUB_TOKEN is not defined.
#    echo "Starting Pull Request analysis by SonarQube..."
#    sonar-scanner -Dsonar.login=$SONAR_TOKEN \
#    -Dsonar.analysis.mode=preview \
#    -Dsonar.github.oauth=$GITHUB_TOKEN \
#    -Dsonar.github.repository=$TRAVIS_REPO_SLUG \
#    -Dsonar.github.pullRequest=$TRAVIS_PULL_REQUEST
#fi
# When neither on master branch nor on a non-external pull request => nothing to do

if [ "$MODULES" != "min" ] && [ "${TARGETOS:0:3}" != "ios" ] && [ "$BUILD_MODE" != "sonarqube" ]; then
    ./botan-test
fi

if [ "$MODULES" != "min" ] && [ "$BUILD_MODE" = "shared" ] && [ "$TARGETOS" = "native" ]
then
    python2 --version
    python3 --version
    LD_LIBRARY_PATH=. python2 src/python/botan.py
    LD_LIBRARY_PATH=. python3 src/python/botan.py
fi

make install
