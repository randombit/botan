#!/usr/bin/env python3

# (C) 2019 Jack Lloyd
# Botan is released under the Simplified BSD License (see license.txt)

import argparse
import subprocess
import logging
import sys
import os
import time

def script_is_disabled(script_name):
    if script_name.find('tls13') >= 0:
        return True
    if script_name.find('sslv2') >= 0:
        return True

    disabled = {
        'test-SSLv3-padding.py',
        'test-serverhello-random.py', # assumes support for SSLv2 hello
    }

    if script_name in disabled:
        return True

    slow = {
        'test-bleichenbacher-workaround.py',
        'test-client-compatibility.py',
        'test-dhe-key-share-random.py',
        'test-dhe-no-shared-secret-padding.py',
        'test-ecdhe-padded-shared-secret.py',
        'test-ecdhe-rsa-key-share-random.py',
        'test-fuzzed-plaintext.py',
        'test-invalid-client-hello-w-record-overflow.py',
        'test-invalid-client-hello.py',
        'test-large-hello.py',
    }
    if script_name in slow:
        return True

    return False

def main(args = None):
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser()

    # TODO generate key and spawn the server on some random port in tmp dir
    # TODO support running tls_server binary under valgrind

    parser.add_argument('--verbose', action='store_true', default=False)
    parser.add_argument('tls-fuzzer-dir')

    args = vars(parser.parse_args(args))

    tlsfuzzer_dir = args['tls-fuzzer-dir']

    if not os.access(tlsfuzzer_dir, os.X_OK):
        raise Exception("Unable to read TLS fuzzer dir")

    tls_scripts_dir = os.path.join(tlsfuzzer_dir, 'scripts')
    if not os.access(tlsfuzzer_dir, os.X_OK):
        raise Exception("Unable to read TLS fuzzer scripts dir")

    scripts = sorted(os.listdir(tls_scripts_dir))

    procs = {}

    for script in scripts:
        if script_is_disabled(script):
            logging.debug('Skipping %s' % (script))
            continue

        procs[script] = subprocess.Popen([sys.executable, os.path.join(tls_scripts_dir, script)],
                                         cwd=tlsfuzzer_dir,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    results = {}

    while len(results) != len(procs):
        time.sleep(.5)
        for (script, proc) in procs.items():

            if script in results:
                continue

            if proc.poll() != None:
                rv = proc.returncode
                results[script] = rv
                if rv == 0:
                    print("PASS %s" % (script))
                else:
                    print("FAIL %s" % (script))
                sys.stdout.flush()
    return 0

if __name__ == '__main__':
    sys.exit(main())
