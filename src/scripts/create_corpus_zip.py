#!/usr/bin/python

# These is used to create fuzzer corpus zip files

# This is primarily used by OSS-Fuzz but might be useful if you were
# deploying the binaries in a custom fuzzer deployment system.

import sys
import os
import zipfile
import stat

def main(args=None):
    if args is None:
        args = sys.argv

    if len(args) != 2 and len(args) != 3:
        print("Usage: %s corpus_dir <output_dir>" % (args[0]))
        return 1

    root_dir = args[1]

    if len(args) == 3:
        output_dir = args[2]
    else:
        output_dir = ''

    if not os.access(root_dir, os.R_OK):
        print("Error could not access directory '%s'" % (root_dir))
        return 1

    for corpus_dir in os.listdir(root_dir):
        if corpus_dir == '.git':
            continue
        subdir = os.path.join(root_dir, corpus_dir)
        if not stat.S_ISDIR(os.stat(subdir).st_mode):
            continue

        zipfile_path = os.path.join(output_dir, '%s.zip' % (corpus_dir))
        zf = zipfile.ZipFile(zipfile_path, 'w', zipfile.ZIP_DEFLATED)
        for f in os.listdir(subdir):
            zf.write(os.path.join(subdir, f), f)
        zf.close()

    return 0

if __name__ == '__main__':
    sys.exit(main())
