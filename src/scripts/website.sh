#!/bin/bash
set -e
# TODO rewrite in Python

#which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

script_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
botan_dir=$(cd ${script_path}/../.. && pwd -P)

SPHINX_CONFIG=${botan_dir}/src/configs/sphinx

WEBSITE_DIR=./botan-website
TMP_DIR=$(mktemp -d)

mkdir -p $WEBSITE_DIR

${botan_dir}/configure.py --with-doxygen --with-sphinx --quiet

# build doxygen
doxygen build/botan.doxy
mv build/docs/doxygen $WEBSITE_DIR/doxygen

# build online manual
cp ${botan_dir}/readme.rst $TMP_DIR/index.rst
cp -r ${botan_dir}/news.rst ${botan_dir}/doc/security.rst $TMP_DIR
echo -e ".. toctree::\n\n   index\n   news\n   security\n   \
Users Manual <https://botan.randombit.net/manual>\n   \
API Reference <https://botan.randombit.net/doxygen>" > $TMP_DIR/contents.rst

sphinx-build -t website -c "$SPHINX_CONFIG" -b "html" $TMP_DIR $WEBSITE_DIR
sphinx-build -t website -c "$SPHINX_CONFIG" -b "html" ${botan_dir}/doc/manual $WEBSITE_DIR/manual
cp ${botan_dir}/license.txt ${botan_dir}/doc/pgpkey.txt $WEBSITE_DIR

rm -rf $WEBSITE_DIR/.doctrees
rm -f $WEBSITE_DIR/.buildinfo
rm -rf $WEBSITE_DIR/manual/.doctrees
rm -f $WEBSITE_DIR/manual/.buildinfo
rm -rf $WEBSITE_DIR/manual/_static
(cd $WEBSITE_DIR/manual && ln -s ../_static .)


# build manual as pdf for download
sphinx-build -t website -c "$SPHINX_CONFIG" -b "latex" ${botan_dir}/doc/manual $TMP_DIR/latex
(cd $TMP_DIR/latex && pdflatex botan.tex && pdflatex botan.tex)
mv $TMP_DIR/latex/botan.pdf $WEBSITE_DIR/manual/botan.pdf

rm -rf www-src build Makefile

