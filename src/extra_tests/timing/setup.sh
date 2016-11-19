#!/bin/sh

mkdir timing-tests/results
mkdir timing-tests/results/bleichenbacher
mkdir timing-tests/results/lucky13sec3
mkdir timing-tests/results/lucky13sec4
mkdir timing-tests/results/lucky13sha256sec3
mkdir timing-tests/results/lucky13sha256sec4
mkdir timing-tests/results/lucky13sha384
mkdir timing-tests/results/manger

if [ ! -d mona-timing-report ]
then
    git clone https://github.com/seecurity/mona-timing-report.git
fi

cd mona-timing-report
ant

cd ../../../../
./configure.py
make -j4
