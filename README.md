CMake version of Botan
======================

This branch is testing area to try out if it is possible to build Botan using CMake.

Ther are a lot of pros and cons which are not repeated here (e.g. #59, #207). Currently the primary use is IDE integration for Botan developers.

Since this branch is missing more features that it has, we start with

Limitations
-----------

* Shared libraries only
* GCC only
* Only the entire lib can be build, no module selection
* No optimization (-O0) enabled everywhere for good debugging
* Copying of headers necessary

Advances over the Botan build system
------------------------------------

* Native support for out-of-tree builds (not well testes but working on Botan)
* Proper dependency management (only re-compile objects that changed)

Requirements
------------

* CMake 2.8 which is the default in the Ubuntu 14.04 LTS tool chain. It is unlikely to get rid of this requirement in the near future.
* GCC 4.8
* Ubuntu packages: liblzma-dev

Todo
----

* Add support for Clang
* Add support for OS X
* Add settings for debug/relese

IDEs
----

IDEs that utilize the CMake build system

* Qt Creator: Native CMake support, great integration for debuggers on GCC, Clang and MSVC

Contributing
------------

* Don't talk – just do it! Pull requests targeting this branch are welcome. Please respect that this a very early stage and we can only do one step at a time.

Getting started
---------------

```
cd workspace
git clone git@github.com:randombit/botan.git
cd botan
git checkout cmake
./configure.py --with-bzip2 --with-zlib --enable-modules="dyn_load"
cd ..
mkdir build-botan
cd build-botan
cmake ../botan
make -j 4
cd ../botan
../build-botan/src/tests/Botan-tests
```
