#!/usr/bin/env python3

# (C) 2017 Jack Lloyd
# Botan is released under the Simplified BSD License (see license.txt)

import os
import sys
import subprocess
import tempfile
import time
import random
import optparse
import string

def run_subprocess(cmd):
    print("Running '%s'" % (' '.join(cmd)))

    proc = subprocess.Popen(cmd, bufsize=-1)
    proc.communicate()

    if proc.returncode != 0:
        print('Running "%s" failed rc %d' % (' '.join(cmd), proc.returncode))
        sys.exit(proc.returncode)

def spawn_server(cmd):
    print("Spawning '%s'" % (' '.join(cmd)))
    return subprocess.Popen(cmd, bufsize=-1)#,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('--type', default='tests',
                      help='Which TLS-Attacker tests to run (tests, policy, fuzzer)')
    parser.add_option('--src-dir', metavar='DIR', default='./src',
                      help='Specify path to botan sources (default "%default")')
    parser.add_option('--verbose', action='store_true',
                      help='Be noisy')

    (options, args) = parser.parse_args(args)

    if len(args) != 3:
        print("Usage: %s botan_cli_exe botan_ci_tools" % (args[0]))
        return 1

    cli_exe = args[1]
    ci_tools = args[2]
    test_type = options.type
    src_dir = options.src_dir

    if test_type not in ['tests', 'policy', 'fuzzer']:
        print("Unknown --type %s" % (options.test_type))
        return 1

    if os.access(cli_exe, os.X_OK) != True:
        print("Unable to find CLI tool at %s" % (cli_exe))
        return 1

    if os.access(src_dir, os.X_OK) != True:
        print("Unable to find src dir at %s" % (src_dir))
        return 1

    test_data_dir = os.path.join(src_dir, 'tests/data')

    lax_policy_txt = os.path.join(test_data_dir, 'tls-policy/compat.txt')
    bsi_policy_txt = os.path.join(test_data_dir, 'tls-policy/bsi.txt')

    tls_attacker_dir = os.path.join(ci_tools, 'TLS-Attacker')
    tls_attacker_jar = os.path.join(tls_attacker_dir, 'TLS-Attacker-1.2.jar')
    tls_attacker_testsuites = os.path.join(tls_attacker_dir, 'resources/testsuite')
    tls_fuzzer_workflows = os.path.join(tls_attacker_dir, 'resources/fuzzing/workflows')

    if os.access(tls_attacker_jar, os.R_OK) != True:
        print("Unable to find TLS-Attacker jar at %s" % (tls_attacker_jar))
        return 1

    rsa_key = tempfile.NamedTemporaryFile(prefix='rsa_key_')
    rsa_crt = tempfile.NamedTemporaryFile(prefix='rsa_crt_')

    run_subprocess([cli_exe, 'keygen', '--algo=RSA', '--params=2048', '--output=%s' % (rsa_key.name)])
    run_subprocess([cli_exe, 'gen_self_signed', rsa_key.name, 'localhost', '--output=%s' % (rsa_crt.name)])

    server_log = 'botan_log.txt'
    server_err_log = 'botan_err_log.txt'

    tls_port = random.randint(50000, 60000)

    botan_server_cmd = [cli_exe, 'tls_server', rsa_crt.name, rsa_key.name,
                        '--port=%d' % (tls_port),
                        '--output='+server_log,
                        '--error-output='+server_err_log]

    java_tls_attacker = ['java', '-jar', tls_attacker_jar,
                         '-loglevel', 'DEBUG' if options.verbose else 'ERROR']
    tls_attacker_opts = ['-tls_timeout', '300', '-connect', 'localhost:%d' % (tls_port)]

    if test_type == 'tests':
        try:
            server_process = spawn_server(botan_server_cmd +
                                          ['--policy=%s' % (lax_policy_txt)])
            time.sleep(1)
            run_subprocess(java_tls_attacker + ['testsuite_server'] + tls_attacker_opts +
                           ['-folder', tls_attacker_testsuites])
        finally:
            server_process.terminate()
    elif test_type == 'policy':
        try:
            server_process = spawn_server(botan_server_cmd +
                                          ['--policy=%s' % (bsi_policy_txt)])
            time.sleep(1)
            run_subprocess(java_tls_attacker + ['testtls_server'] + tls_attacker_opts +
                           ['-policy', bsi_policy_txt])
        finally:
            server_process.terminate()
    elif test_type == 'fuzzer':

        template_mapping = {
            'rsa_key': rsa_key.name,
            'rsa_cert': rsa_crt.name,
            'botan_cli': cli_exe,
            'workflow_dir': tls_fuzzer_workflows,
            'fuzz_policy': lax_policy_txt,
            'tls_port': str(tls_port),
            'PORT': '$PORT' # this is a var for TLS-Attacker don't touch it
        }

        template_txt = open(os.path.join(src_dir, 'scripts/fuzzer.xml')).read()

        config = string.Template(template_txt).substitute(template_mapping)

        fuzzer_config = tempfile.NamedTemporaryFile(prefix='fuzzer_cfg_', delete=False)
        fuzzer_config.write(config.encode('ascii'))
        fuzzer_config.close()

        run_subprocess(java_tls_attacker + ['multi_fuzzer'] +
                       ['-startup_command_file', fuzzer_config.name])

if __name__ == '__main__':
    sys.exit(main())
