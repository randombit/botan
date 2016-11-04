#!/bin/bash
set -e
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

SPHINX_CONFIG=./src/build-data/sphinx
SPHINX_BUILDER="html"

WEBSITE_DIR=./www-botan
WEBSITE_SRC_DIR=./www-src

rm -rf $WEBSITE_SRC_DIR $WEBSITE_DIR
mkdir -p $WEBSITE_SRC_DIR

cp readme.rst $WEBSITE_SRC_DIR/index.rst
cp -r news.rst doc/security.rst $WEBSITE_SRC_DIR
echo -e ".. toctree::\n\n   index\n   news\n   security\n" > $WEBSITE_SRC_DIR/contents.rst

sphinx-build -t website -c "$SPHINX_CONFIG" -b "$SPHINX_BUILDER" $WEBSITE_SRC_DIR $WEBSITE_DIR
sphinx-build -t website -c "$SPHINX_CONFIG" -b "$SPHINX_BUILDER" doc/manual $WEBSITE_DIR/manual
rm -rf $WEBSITE_DIR/.doctrees
rm -f $WEBSITE_DIR/.buildinfo
rm -rf $WEBSITE_DIR/manual/.doctrees
rm -f $WEBSITE_DIR/manual/.buildinfo
cp license.txt doc/pgpkey.txt $WEBSITE_DIR

doxygen build/botan.doxy
mv build/docs/doxygen $WEBSITE_DIR/doxygen
