#!/bin/bash
set -e
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

SPHINX_CONFIG=./src/build-data/sphinx

WEBSITE_DIR=./www-botan
WEBSITE_SRC_DIR=./www-src

rm -rf $WEBSITE_SRC_DIR $WEBSITE_DIR
mkdir -p $WEBSITE_SRC_DIR

# build online manual
cp readme.rst $WEBSITE_SRC_DIR/index.rst
cp -r news.rst doc/security.rst $WEBSITE_SRC_DIR
echo -e ".. toctree::\n\n   index\n   news\n   security\n   \
Users Manual <https://botan.randombit.net/manual>\n   \
API Reference <https://botan.randombit.net/doxygen>" > $WEBSITE_SRC_DIR/contents.rst

sphinx-build -t website -c "$SPHINX_CONFIG" -b "html" $WEBSITE_SRC_DIR $WEBSITE_DIR
sphinx-build -t website -c "$SPHINX_CONFIG" -b "html" doc/manual $WEBSITE_DIR/manual
rm -rf $WEBSITE_DIR/.doctrees
rm -f $WEBSITE_DIR/.buildinfo
rm -rf $WEBSITE_DIR/manual/.doctrees
rm -f $WEBSITE_DIR/manual/.buildinfo
cp license.txt doc/pgpkey.txt $WEBSITE_DIR

# build manual as pdf for download
sphinx-build -t website -c "$SPHINX_CONFIG" -b "latex" doc/manual handbook-latex
(cd handbook-latex && pdflatex botan.tex && pdflatex botan.tex)
cp handbook-latex/botan.pdf $WEBSITE_DIR/manual/botan.pdf

# build doxygen
doxygen build/botan.doxy
mv build/docs/doxygen $WEBSITE_DIR/doxygen
