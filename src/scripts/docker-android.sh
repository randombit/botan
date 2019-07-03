VERSION=`./configure.py --version`
mkdir -p docker-builds
docker build -f src/scripts/Dockerfile.android --force-rm -t botan-android-${VERSION} --build-arg SDK=${SDK} .
docker create --name botan-android-${VERSION} botan-android-${VERSION}
docker cp botan-android-${VERSION}:/botan/android docker-builds
docker rm -f botan-android-${VERSION}
