#!/bin/bash

# This is probably only useful if run on my machine, which is not
# exactly ideal

SELECTOR=h:net.randombit.botan.1_8
KEY_ID=EFBADFBC
MTN_DB=/storage/mtn/botan.mtn
WEB_DIR=~/projects/www
DIST_DIR=~/Botan-dist

# You shouldn't have to change anything after this
mkdir -p $DIST_DIR
cd $DIST_DIR

mtn -d $MTN_DB checkout -r $SELECTOR Botan

VERSION=$(Botan/configure.py --version)

mv Botan Botan-$VERSION

cd Botan-$VERSION
rm -rf _MTN
rm -f .mtn-ignore

# Build docs
cd doc

for doc in api tutorial building
do
  latex $doc.tex
  latex $doc.tex
  dvips $doc.dvi -o
  pdflatex $doc.tex
  pdflatex $doc.tex
  cp $doc.pdf $DIST_DIR
  mv $doc.ps $DIST_DIR
  # Clean up after TeX
  rm -f $doc.aux $doc.log $doc.dvi $doc.toc
done

cp log.txt ../..

cd .. # topdir
cd .. # now in DIST_DIR

tar -cf Botan-$VERSION.tar Botan-$VERSION

bzip2 -9 -k Botan-$VERSION.tar
gzip -9 Botan-$VERSION.tar

rm -rf Botan-$VERSION

mv Botan-$VERSION.tar.gz Botan-$VERSION.tgz
mv Botan-$VERSION.tar.bz2 Botan-$VERSION.tbz

echo "*****************************************************"
read -a PASSWORD -p "Enter PGP password (or ^C to skip signatures): "

echo $PASSWORD | gpg --batch --armor -b --passphrase-fd 0 -u $KEY_ID Botan-$VERSION.tgz
echo $PASSWORD | gpg --batch --armor -b --passphrase-fd 0 -u $KEY_ID Botan-$VERSION.tbz

mv Botan-$VERSION.tgz* $WEB_DIR/files/botan/v1.8
mv Botan-$VERSION.tbz* $WEB_DIR/files/botan/v1.8
