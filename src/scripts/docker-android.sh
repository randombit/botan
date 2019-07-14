VERSION=`./configure.py --version`
mkdir -p docker-builds
docker build -f src/scripts/Dockerfile.android --force-rm -t botan-android-${VERSION} \
    --build-arg ANDROID_ARCH=${ANDROID_ARCH} \
    --build-arg ANDROID_ARCH_SUF=${ANDROID_ARCH_SUF} \
    --build-arg ANDROID_SDK_VER=${ANDROID_SDK_VER} \
    --build-arg ANDROID_TOOLCHAIN_SUF=${ANDROID_TOOLCHAIN_SUF} \
    .
docker create --name botan-android-${VERSION} botan-android-${VERSION}
docker cp botan-android-${VERSION}:/botan/android docker-builds
docker rm -f botan-android-${VERSION}
