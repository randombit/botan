#!/usr/bin/python

"""
Generate the Botan website

(C) 2017 Jack Lloyd
"""

import optparse # pylint: disable=deprecated-module
import subprocess
import sys
import errno
import shutil
import tempfile
import os

def run_and_check(proc, proc_name):
    (stdout, stderr) = proc.communicate()

    if proc.returncode != 0:
        print("Error running ", proc_name)
        print(stdout)
        print(stderr)
        sys.exit(1)

def configure_build(botan_dir, build_dir):

    configure = subprocess.Popen([os.path.join(botan_dir, 'configure.py'),
                                  '--with-doxygen', '--with-sphinx',
                                  '--with-build-dir=%s' % (build_dir)],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
    run_and_check(configure, 'configure.py')

def run_doxygen(tmp_dir, output_dir):
    doxygen = subprocess.Popen(['doxygen', os.path.join(tmp_dir, 'build/botan.doxy')],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    run_and_check(doxygen, 'doxygen')
    shutil.move(os.path.join(tmp_dir, 'build/docs/doxygen'), output_dir)

def run_sphinx(botan_dir, tmp_dir, output_dir):

    sphinx_config = os.path.join(botan_dir, 'src/configs/sphinx')
    sphinx_dir = os.path.join(tmp_dir, 'sphinx')
    os.mkdir(sphinx_dir)

    shutil.copyfile(os.path.join(botan_dir, 'readme.rst'),
                    os.path.join(sphinx_dir, 'index.rst'))

    for f in ['news.rst', os.path.join('doc', 'security.rst')]:
        shutil.copy(os.path.join(botan_dir, f), sphinx_dir)

    toc = """.. toctree::

   index
   news
   security
   Users Manual <https://botan.randombit.net/manual>
   API Reference <https://botan.randombit.net/doxygen>
"""

    contents_rst = open(os.path.join(sphinx_dir, 'contents.rst'), 'w')
    contents_rst.write(toc)
    contents_rst.close()

    sphinx_invoke = ['sphinx-build', '-t', 'website', '-c', sphinx_config, '-b', 'html']
    sphinx_website = subprocess.Popen(sphinx_invoke + [sphinx_dir, output_dir],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    run_and_check(sphinx_website, 'sphinx-build website')

    sphinx_manual = subprocess.Popen(sphinx_invoke + [os.path.join(botan_dir, 'doc/manual'),
                                                      os.path.join(output_dir, 'manual')],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    run_and_check(sphinx_manual, 'sphinx-build manual')

    shutil.rmtree(os.path.join(output_dir, '.doctrees'))
    shutil.rmtree(os.path.join(output_dir, 'manual', '.doctrees'))
    os.remove(os.path.join(output_dir, '.buildinfo'))
    os.remove(os.path.join(output_dir, 'manual', '.buildinfo'))

    # share _static subdirs
    shutil.rmtree(os.path.join(output_dir, 'manual', '_static'))
    os.symlink('../_static', os.path.join(output_dir, 'manual', '_static'))

def main(args):
    parser = optparse.OptionParser()

    parser.add_option('--output-dir', default=None,
                      help="Where to write output")

    (options, args) = parser.parse_args(args)

    output_dir = options.output_dir
    tmp_dir = tempfile.mkdtemp(prefix='botan_website_')

    # assumes we live in src/scripts
    botan_dir = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                              "..", ".."))

    if os.access(os.path.join(botan_dir, 'configure.py'), os.X_OK) is False:
        print("Can't find configure.py in %s", botan_dir)
        sys.exit(1)

    if output_dir is None:
        cwd = os.getcwd()

        if os.path.basename(cwd) == 'botan-website':
            output_dir = '.'
        else:
            output_dir = os.path.join(cwd, 'botan-website')

            try:
                os.mkdir(output_dir)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    pass
                else:
                    raise e

    for subdir in ['_static', '_sources', 'doxygen', 'manual']:
        try:
            shutil.rmtree(os.path.join(output_dir, subdir))
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass
            else:
                print("Error removing dir", e)
                sys.exit(1)

    configure_build(botan_dir, tmp_dir)
    run_doxygen(tmp_dir, output_dir)
    run_sphinx(botan_dir, tmp_dir, output_dir)

    for f in ['doc/pgpkey.txt', 'license.txt']:
        shutil.copy(os.path.join(botan_dir, f), output_dir)

    shutil.rmtree(tmp_dir)

if __name__ == '__main__':
    sys.exit(main(sys.argv))
