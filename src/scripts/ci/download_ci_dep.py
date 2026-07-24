#!/usr/bin/env python3

"""
(C) 2026 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import argparse
import configparser
import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.request


def load_config(dep_name):
    config_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               '..', '..', 'configs', 'ci_deps.conf')
    config = configparser.ConfigParser()
    config.read(config_path)

    if dep_name not in config:
        print("Unknown dependency %s - available options are %s" % (
            dep_name, ','.join(config.sections())))
        sys.exit(1)

    section = config[dep_name]
    url = section.get('url')
    sha256 = section.get('sha256')
    if not url or not sha256:
        print("Bad config entry for %s" % (dep_name))
        sys.exit(1)

    return url, sha256

def download(url, fileobj, max_mb):
    max_bytes = max_mb * 1024 * 1024
    req = urllib.request.Request(url)
    hasher = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(req) as resp:
        content_length = resp.headers.get('Content-Length')
        content_length = int(content_length) if content_length is not None else None

        if (content_length is not None) and (content_length > max_bytes):
            raise RuntimeError("Download of %s too large, server reports %d bytes" % (url, content_length))

        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if (content_length is not None) and (total > content_length):
                raise RuntimeError("Server sent too much data for %s, reported %d" % (url, content_length))
            if total > max_bytes:
                raise RuntimeError("Server sent too much data for %s" % (url))
            hasher.update(chunk)
            fileobj.write(chunk)

    return hasher.hexdigest(), total

def main():
    parser = argparse.ArgumentParser(description='Download a CI dependency with integrity verification')
    parser.add_argument('dep_name', help='Dependency name (section in ci_deps.conf)')
    parser.add_argument('output_path', nargs='?', default=None,
                        help='Output file path (default: filename from URL in current directory)')
    parser.add_argument('--max-download-mb', default=48, type=int,
                        help='Maximum download size in MB')
    parser.add_argument('--extract', default=None, metavar='CMD',
                        help='Extract after download using CMD template (eg "tar -xf {file}")')
    args = parser.parse_args()

    url, expected_sha256 = load_config(args.dep_name)

    if args.extract:
        final_path = None
        fd, tmp_path = tempfile.mkstemp(prefix='ci_dep_')
    else:
        if args.output_path:
            final_path = args.output_path
        else:
            final_path = os.path.basename(urllib.request.url2pathname(url.split('?')[0]))
        fd, tmp_path = tempfile.mkstemp(prefix='.ci_dep_',
                                        dir=os.path.dirname(final_path) or '.')

    try:
        with os.fdopen(fd, 'wb') as f:
            computed_sha256, total = download(url, f, args.max_download_mb)

        if computed_sha256 != expected_sha256:
            print("Checksum failure downloading %s - got %s (%d bytes)" % (
                url, computed_sha256, total))
            return 1

        if args.extract:
            cmd = args.extract.replace('{file}', tmp_path)
            subprocess.run(cmd, shell=True, check=True)
        else:
            os.replace(tmp_path, final_path)
            print(final_path)

        return 0
    except Exception as e:
        print(str(e))
        return 1
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass

if __name__ == '__main__':
    sys.exit(main())
