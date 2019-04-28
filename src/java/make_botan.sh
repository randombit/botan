#!/bin/sh
jextract /usr/local/include/botan-2/botan/ffi.h -L/usr/local/lib/ -I/usr/local/include/botan-2/ -l botan-2 -t net.randombit.Botan --record-library-path -o ./libs/botan2.jar
