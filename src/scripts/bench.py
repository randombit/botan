#!/usr/bin/python

"""
Compare Botan with OpenSSL using their respective benchmark utils

(C) 2017 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)

TODO
 - Also compare RSA, ECDSA, ECDH
 - Output pretty graphs with matplotlib
"""

import logging
import os
import sys
import optparse # pylint: disable=deprecated-module
import subprocess
import re
import json

def setup_logging(options):
    if options.verbose:
        log_level = logging.DEBUG
    elif options.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO

    class LogOnErrorHandler(logging.StreamHandler, object):
        def emit(self, record):
            super(LogOnErrorHandler, self).emit(record)
            if record.levelno >= logging.ERROR:
                sys.exit(1)

    lh = LogOnErrorHandler(sys.stdout)
    lh.setFormatter(logging.Formatter('%(levelname) 7s: %(message)s'))
    logging.getLogger().addHandler(lh)
    logging.getLogger().setLevel(log_level)

def run_command(cmd):
    logging.debug("Running '%s'", ' '.join(cmd))

    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True)
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        logging.error("Running command %s failed ret %d", ' '.join(cmd), proc.returncode)

    return stdout + stderr

def get_openssl_version(openssl):
    output = run_command([openssl, 'version'])

    openssl_version_re = re.compile(r'OpenSSL ([0-9a-z\.]+) .*')

    match = openssl_version_re.match(output)

    if match:
        return match.group(1)
    else:
        logging.warning("Unable to parse OpenSSL version output %s", output)
        return output

def get_botan_version(botan):
    return run_command([botan, 'version']).strip()

EVP_MAP = {
    'Blowfish': 'bf-ecb',
    'AES-128/GCM': 'aes-128-gcm',
    'AES-256/GCM': 'aes-256-gcm',
    'ChaCha20': 'chacha20',
    'MD5': 'md5',
    'SHA-1': 'sha1',
    'RIPEMD-160': 'ripemd160',
    'SHA-256': 'sha256',
    'SHA-384': 'sha384',
    'SHA-512': 'sha512'
    }

def run_openssl_bench(openssl, algo):

    logging.info('Running OpenSSL benchmark for %s', algo)

    cmd = [openssl, 'speed', '-mr']

    if algo in EVP_MAP:
        cmd += ['-evp', EVP_MAP[algo]]
    else:
        cmd += [algo]

    output = run_command(cmd)

    buf_header = re.compile(r'\+DT:([a-z0-9-]+):([0-9]+):([0-9]+)$')
    res_header = re.compile(r'\+R:([0-9]+):[a-z0-9-]+:([0-9]+\.[0-9]+)$')
    ignored = re.compile(r'\+(H|F):.*')

    results = []

    result = None

    for l in output.splitlines():
        if ignored.match(l):
            continue

        if result is None:
            match = buf_header.match(l)
            if match is None:
                logging.error("Unexpected output from OpenSSL %s", l)

            result = {'algo': algo, 'buf_size': int(match.group(3))}
        else:
            match = res_header.match(l)

            result['bytes'] = int(match.group(1)) * result['buf_size']
            result['runtime'] = float(match.group(2))
            result['bps'] = int(result['bytes'] / result['runtime'])
            results.append(result)
            result = None

    return results

def run_botan_bench(botan, runtime, buf_sizes, algo):

    runtime = .05

    cmd = [botan, 'speed', '--format=json', '--msec=%d' % int(runtime * 1000),
           '--buf-size=%s' % (','.join([str(i) for i in buf_sizes])), algo]
    output = run_command(cmd)
    output = json.loads(output)

    return output

class BenchmarkResult(object):
    def __init__(self, algo, buf_sizes, openssl_results, botan_results):
        self.algo = algo
        self.results = {}

        def find_result(results, sz):
            for r in results:
                if 'buf_size' in r and r['buf_size'] == sz:
                    return r['bps']
            raise Exception("Could not find expected result in data")

        for buf_size in buf_sizes:
            self.results[buf_size] = {
                'openssl': find_result(openssl_results, buf_size),
                'botan': find_result(botan_results, buf_size)
            }

    def result_string(self):

        out = ""
        for (k, v) in self.results.items():
            out += "algo %s buf_size % 6d botan % 12d bps openssl % 12d bps adv %.02f\n" % (
                self.algo, k, v['botan'], v['openssl'], float(v['botan']) / v['openssl'])
        return out

def bench_algo(openssl, botan, algo):
    openssl_results = run_openssl_bench(openssl, algo)

    buf_sizes = sorted([x['buf_size'] for x in openssl_results])
    runtime = sum(x['runtime'] for x in openssl_results) / len(openssl_results)

    botan_results = run_botan_bench(botan, runtime, buf_sizes, algo)

    return BenchmarkResult(algo, buf_sizes, openssl_results, botan_results)

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('--verbose', action='store_true', default=False, help="be noisy")
    parser.add_option('--quiet', action='store_true', default=False, help="be very quiet")

    parser.add_option('--openssl-cli', metavar='PATH',
                      default='/usr/bin/openssl',
                      help='Path to openssl binary (default %default)')

    parser.add_option('--botan-cli', metavar='PATH',
                      default='/usr/bin/botan',
                      help='Path to botan binary (default %default)')

    (options, args) = parser.parse_args(args)

    setup_logging(options)

    openssl = options.openssl_cli
    botan = options.botan_cli

    if os.access(openssl, os.X_OK) is False:
        logging.error("Unable to access openssl binary at %s", openssl)

    if os.access(botan, os.X_OK) is False:
        logging.error("Unable to access botan binary at %s", botan)

    openssl_version = get_openssl_version(openssl)
    botan_version = get_botan_version(botan)

    logging.info("Comparing Botan %s with OpenSSL %s", botan_version, openssl_version)

    for algo in sorted(EVP_MAP.keys()):
        result = bench_algo(openssl, botan, algo)
        print(result.result_string())


    return 0

if __name__ == '__main__':
    sys.exit(main())
