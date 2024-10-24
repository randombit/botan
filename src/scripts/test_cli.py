#!/usr/bin/env python3

"""
(C) 2018,2019 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import asyncio
import base64
import binascii
import json
import logging
import multiprocessing
import optparse # pylint: disable=deprecated-module
import os
import platform
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from multiprocessing.pool import ThreadPool
from http.client import HTTPSConnection
from http.server import HTTPServer, BaseHTTPRequestHandler

# pylint: disable=global-statement,unused-argument

CLI_PATH = None
ASYNC_TIMEOUT = 15 # seconds
TEST_DATA_DIR = '.'
ONLINE_TESTS = False
TESTS_RUN = 0
TESTS_FAILED = 0

def run_socket_tests():
    # Some of the socket tests fail on FreeBSD CI, for reasons unknown.
    # Connecting to the server port fails. Possibly a local firewall?
    return platform.system().lower() != "freebsd"

def run_online_tests():
    return ONLINE_TESTS

class TestLogHandler(logging.StreamHandler):
    def emit(self, record):
        # Do the default stuff first
        super().emit(record)
        if record.levelno >= logging.ERROR:
            global TESTS_FAILED
            TESTS_FAILED += 1

def setup_logging(options):
    if options.verbose:
        log_level = logging.DEBUG
    elif options.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO

    lh = TestLogHandler(sys.stdout)
    lh.setFormatter(logging.Formatter('%(levelname) 7s: %(message)s'))
    logging.getLogger().addHandler(lh)
    logging.getLogger().setLevel(log_level)

def port_for(service):
    # use ports in range 63000-63100 for tests, which will hopefully
    # avoid conflicts with local services

    base_port = 63000

    port_assignments = {
        'tls_server': 0,
        'tls_http_server': 1,
        'tls_proxy': 2,
        'tls_proxy_backend': 3,
        'roughtime': 4,
    }

    if service in port_assignments:
        return base_port + port_assignments.get(service)
    else:
        logging.warning("Unknown service '%s', update port_for function", service)
        return base_port + random.randint(30, 100)


class AsyncTestProcess:
    """
    An asyncio wrapper around a long-running process with some helpers to
    interact with the it. Typically, users will derive from this and
    implement an asynchronous resource manager based on this.

    Subclasses should await _launch() in their __aenter__() and _finalize()
    in their __aexit__() methods.

    This base class handles proper (and guaranteed) termination of the
    process and collects its stdout for inspection by the test code.
    """

    def __init__(self, name):
        self._name = name
        self._proc = None
        self._stdout = b''
        self._all_clear = False

    def all_clear(self):
        self._all_clear = True

    @property
    def returncode(self):
        return self._proc.returncode if self._proc else None

    @property
    def stdout(self):
        return self._stdout.decode('utf-8')

    async def _launch(self, cmd, start_sentinel = None):
        """Launch the process and wait for it to reach a defined state.

        If provided this listens on the process' stdout until a given sentinel
        string was printed. This is useful to wait for a server to be ready.
        """
        logging.debug("Executing: '%s'", ' '.join(cmd))

        try:
            self._proc = await asyncio.create_subprocess_exec(*cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            if start_sentinel:
                await self._read_stdout_until(start_sentinel)
        except:
            await self._finalize()
            raise

    async def _write_to_stdin(self, data):
        self._proc.stdin.write(data)
        await self._proc.stdin.drain()

    async def _read_stdout_until(self, needle):
        """Read from the process' stdout until a given string is found.

        If the process does not report back in time, or closes its stdout
        prematurely, this function will log an error and throw.
        """

        try:
            self._stdout += await asyncio.wait_for(self._proc.stdout.readuntil(needle), timeout=ASYNC_TIMEOUT)
        except asyncio.IncompleteReadError as e:
            logging.error("%s did not report back as expected", self._name)
            self._stdout += e.partial
            raise
        except asyncio.TimeoutError:
            logging.error("%s ran into a timeout before reporting back", self._name)
            raise

    async def _close_stdin_read_stdout_to_eof_and_wait_for_termination(self): # pylint: disable=invalid-name
        """Gracefully signal the process to terminate by closing its stdin.

        If the process does not terminate in time, this function will log an
        error and throw.
        """
        self._proc.stdin.close()
        try:
            self._stdout += await asyncio.wait_for(self._proc.stdout.read(), timeout=ASYNC_TIMEOUT)
        except asyncio.TimeoutError:
            logging.error("%s did not close their stdout as expected", self._name)
            raise

        try:
            return await asyncio.wait_for(self._proc.wait(), timeout=ASYNC_TIMEOUT)
        except asyncio.TimeoutError:
            logging.error("%s did not terminate in time", self._name)
            raise

    async def _finalize(self):
        """Make sure the process is terminated and collect its final output."""
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=ASYNC_TIMEOUT)
        except asyncio.TimeoutError:
            logging.error("%s did not terminate in time, will kill it...", self._name)
            self._proc.kill()
        finally:
            (final_stdout, final_stderr) = await self._proc.communicate()
            self._stdout += final_stdout
            logging.debug("%s finished with return code: %d", self._name, self._proc.returncode)
            logging.debug("%s said (stdout): %s", self._name, self._stdout.decode('utf-8'))
            if final_stderr:
                logging.log(logging.ERROR if not self._all_clear else logging.DEBUG,
                            "%s said (stderr): %s", self._name, final_stderr.decode('utf-8'))

class ServerCertificateSuite:
    """Generates a temporary self-signed certificate chain for testing TLS servers."""

    def __init__(self, tmp_dir, ecdsa_algo, hash_algo):
        tmp_subdir = tempfile.mkdtemp(prefix='botan_cli_', dir=tmp_dir)
        self.private_key = os.path.join(tmp_subdir, 'priv.pem')
        self.ca_cert = os.path.join(tmp_subdir, 'ca.crt')
        crt_req = os.path.join(tmp_subdir, 'crt.req')
        self.cert = os.path.join(tmp_subdir, 'server.crt')

        test_cli("keygen", ["--algo=ECDSA", f"--params={ecdsa_algo}", f"--output={self.private_key}"], "")
        test_cli("gen_self_signed", [self.private_key, "CA", "--ca", "--country=VT", "--dns=ca.example", f"--hash={hash_algo}", f"--output={self.ca_cert}"], "")
        test_cli("cert_verify", self.ca_cert, "Certificate did not validate - Cannot establish trust")
        test_cli("gen_pkcs10", [f"{self.private_key}", "localhost", f"--output={crt_req}"])
        test_cli("sign_cert", [self.ca_cert, self.private_key, crt_req, f"--output={self.cert}"])


def test_cli(cmd, cmd_options,
             expected_output=None,
             cmd_input=None,
             expected_stderr=None,
             use_drbg=True,
             extra_env=None,
             timeout=None):
    global TESTS_RUN

    TESTS_RUN += 1

    opt_list = []

    if isinstance(cmd_options, str):
        opt_list = cmd_options.split(' ')
    elif isinstance(cmd_options, list):
        opt_list = cmd_options

    if use_drbg:
        fixed_drbg_seed = "802" * 32
        drbg_options = ['--rng-type=drbg', '--drbg-seed=' + fixed_drbg_seed]
    else:
        drbg_options = []

    cmdline = [CLI_PATH, cmd] + drbg_options + opt_list

    logging.debug("Executing '%s'", ' '.join([CLI_PATH, cmd] + opt_list))

    stdout = None
    stderr = None

    try:
        if cmd_input is None:
            proc_env = None
            if extra_env:
                proc_env = os.environ
                for (k,v) in extra_env.items():
                    proc_env[k] = v

            proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=proc_env)
            (stdout, stderr) = proc.communicate(timeout=timeout)
        else:
            proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (stdout, stderr) = proc.communicate(cmd_input.encode(), timeout=timeout)
    except subprocess.TimeoutExpired:
        logging.error("Reached timeout of %d seconds for command %s", timeout, cmdline)
        proc.kill()
        (stdout, stderr) = proc.communicate()

    stdout = stdout.decode('ascii').strip()
    stderr = stderr.decode('ascii').strip()

    if "\r\n" in stdout:
        stdout = stdout.replace("\r\n", "\n")

    if stderr:
        if expected_stderr is None:
            logging.error("Got output on stderr %s (stdout was %s) for command %s", stderr, stdout, cmdline, stack_info=True)
        else:
            if stderr != expected_stderr:
                logging.error("Got output on stderr %s which did not match expected value %s", stderr, expected_stderr, stack_info=True)
    else:
        if expected_stderr is not None:
            logging.error('Expected output on stderr but got nothing', stack_info=True)

    if expected_output is not None:
        if stdout != expected_output:
            logging.error("Got unexpected output running cmd %s %s", cmd, cmd_options, stack_info=True)
            logging.info("Output lengths %d vs expected %d", len(stdout), len(expected_output))
            logging.info("Got %s", stdout)
            logging.info("Exp %s", expected_output)

    return stdout

def check_for_command(cmd):
    cmdline = [CLI_PATH, 'has_command', cmd]
    proc = subprocess.Popen(cmdline)
    proc.communicate()

    return proc.returncode == 0

def cli_config_tests(_tmp_dir):
    prefix = test_cli("config", "prefix")
    cflags = test_cli("config", "cflags")
    ldflags = test_cli("config", "ldflags")
    libs = test_cli("config", "libs")

    if platform.system() == 'Windows':
        if len(prefix) < 4 or prefix[1] != ':' or prefix[2] != '\\':
            logging.error("Bad prefix %s", prefix)
        if not ldflags.endswith(("-L%s\\lib" % (prefix))):
            logging.error("Bad ldflags %s", ldflags)
    else:
        if len(prefix) < 4 or prefix[0] != '/':
            logging.error("Bad prefix %s", prefix)
        if not ldflags.endswith(("-L%s/lib" % (prefix))):
            logging.error("Bad ldflags %s", ldflags)
    if ("-I%s/include/botan-3" % (prefix)) not in cflags:
        logging.error("Bad cflags %s", cflags)
    if "-lbotan-3" not in libs:
        logging.error("Bad libs %s", libs)

def cli_help_tests(_tmp_dir):
    output = test_cli("help", None, None)

    # Maybe test format somehow??
    if len(output) < 500:
        logging.error("Help output seems very short")

def cli_version_tests(_tmp_dir):
    output = test_cli("version", None, None)

    version_re = re.compile(r'[0-9]\.[0-9]+\.[0-9](\-[a-z]+[0-9]+)?')
    if not version_re.match(output):
        logging.error("Unexpected version output %s", output)

    output = test_cli("version", ["--full"], None, None)
    version_full_re = re.compile(r'Botan [0-9]\.[0-9]+\.[0-9](\-[a-z]+[0-9]+)? \(.* revision .*, distribution .*\)$')
    if not version_full_re.match(output):
        logging.error("Unexpected version output %s", output)

def cli_is_prime_tests(_tmp_dir):
    test_cli("is_prime", "5", "5 is probably prime")
    test_cli("is_prime", "9", "9 is composite")
    test_cli("is_prime", "548950623407687320763", "548950623407687320763 is probably prime")

def cli_gen_prime_tests(_tmp_dir):
    test_cli("gen_prime", "64", "15568813029901363163")
    test_cli("gen_prime", "128", "287193909494025008847286845478788766073")

def cli_cycle_counter(_tmp_dir):
    output = test_cli("cpu_clock", None, None)

    if output.startswith('No CPU cycle counter on this machine'):
        return

    have_clock_re = re.compile(r'Estimated CPU clock [0-9\.]+ (M|G)Hz')

    if have_clock_re.match(output):
        return

    logging.error('Unexpected output from cpu_clock: %s', output)

def cli_entropy_tests(_tmp_dir):
    output = test_cli("entropy", ["all"], None)

    status_re = re.compile('Polling [a-z0-9_]+ gathered [0-9]+ bytes in [0-9]+ outputs with estimated entropy [0-9]+')
    unavail_re = re.compile('Source [a-z0-9_]+ is unavailable')
    comp_re = re.compile('Sample from [a-z0-9_]+ was .* compressed from [0-9]+ bytes to [0-9]+ bytes')
    output_re = re.compile(r'[A-F0-9]+(...)?')

    status_next = True

    for line in output.split('\n'):
        if comp_re.match(line):
            continue

        if status_next:
            if status_re.match(line) is not None:
                status_next = False
            elif unavail_re.match(line) is not None:
                pass
            else:
                logging.error('Unexpected status line %s', line)
                status_next = False
        else:
            if output_re.match(line) is None:
                logging.error('Unexpected sample line %s', line)
            status_next = True

def cli_factor_tests(_tmp_dir):
    test_cli("factor", "97", "97: 97")
    test_cli("factor", "9753893489562389", "9753893489562389: 21433 455087644733")
    test_cli("factor", "12019502040659149507", "12019502040659149507: 3298628633 3643787579")

def cli_mod_inverse_tests(_tmp_dir):
    test_cli("mod_inverse", "97 802", "339")
    test_cli("mod_inverse", "98 802", "0")

def cli_base64_tests(_tmp_dir):
    test_cli("base64_enc", "-", "YmVlcyE=", "bees!")
    test_cli("base64_dec", "-", "bees!", "YmVlcyE=")

def cli_base32_tests(_tmp_dir):
    test_cli("base32_enc", "-", "MJSWK4ZB", "bees!")
    test_cli("base32_dec", "-", "bees!", "MJSWK4ZB")

def cli_base58_tests(_tmp_dir):
    test_cli("base58_enc", "-", "C6sRAr4", "bees!")
    test_cli("base58_dec", "-", "bees!", "C6sRAr4")

    test_cli("base58_enc", ["--check", "-"], "Cjv15cdjaBc", "F00F")
    test_cli("base58_dec", ["--check", "-"], "F00F", "Cjv15cdjaBc")

def cli_hex_tests(_tmp_dir):
    test_cli("hex_enc", "-", "6265657321", "bees!")
    test_cli("hex_dec", "-", "bees!", "6265657321")

def cli_hash_tests(_tmp_dir):
    test_cli("hash", "--algo=SHA-256",
             "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 -", "")

    test_cli("hash", "--algo=SHA-256",
             "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD -", "abc")

    test_cli("hash", ["--algo=SHA-256", "--format=base64"],
             "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0= -", "abc")

    test_cli("hash", ["--algo=SHA-224", "--format=base58", "--no-fsname"],
             "MuGc8HkSVyJjfMjPM5UQikPToBTzNucEghcGLe", "abc")

    test_cli("hash", ["--algo=SHA-224", "--format=base58check", "--no-fsname"],
             "3MmfMqgrhemdVa9bDAGfooukbviWtKMBx2xauL2RsyAe", "abc")

def cli_hmac_tests(tmp_dir):
    key_file = os.path.join(tmp_dir, 'hmac.key')

    test_cli("rng", ["64", "--output=%s" % (key_file)], "")

    test_cli("hmac", ["--no-fsname", "--hash=SHA-384", key_file, key_file],
             "E3A8529377030B28A7DBDFC50DDEC8E4ECEFB6EA850D95EB785938CD3E3AFEF9EF8B08AF219C1496633193468AB755CB")

def cli_bcrypt_tests(_tmp_dir):
    test_cli("gen_bcrypt", "--work-factor=4 s3kr1t",
             "$2a$04$0.8G7o08XYwvBBWA3l0WUujtwoGZgGDzVSN8fNkNqXikcK4A3lHPS")

    test_cli("check_bcrypt", "s3kr1t $2a$04$gHX4Qg7pDSJuXiPXnmt8leyb.FFzX1Bv4rXwIj2cPSakJ8zNnhIka",
             "Password is valid")

    test_cli("check_bcrypt", "santa $2a$04$gHX4Qg7pDSJuXiPXnmt8leyb.FFzX1Bv4rXwIj2cPSakJ8zNnhIka",
             "Password is NOT valid")

def cli_argon2_tests(_tmp_dir):
    password = "s3kr1t"
    expected = "$argon2id$v=19$m=8,t=1,p=1$2A+I9q2+ZayxDDYC5n2YWw$/Lhx+Jbtlpw+Kxpskfv7+AKhBL/5ebalTJkVC1O5+1E"
    test_cli("gen_argon2", ['--mem=8', password], expected)
    test_cli("gen_argon2", ['--mem=8', '--t=1', password], expected)
    test_cli("gen_argon2", ['--mem=8', '--t=1', '--p=1', password], expected)

    test_cli("check_argon2", [password, expected], "Password is valid")
    test_cli("check_argon2", ["guessing", expected], "Password is NOT valid")

def cli_gen_dl_group_tests(_tmp_dir):

    pem = """-----BEGIN X9.42 DH PARAMETERS-----
MIIBJAKBgwTw7LQiLkXJsrgMVQxTPlWaQlYz/raZ+5RtIZe4YluQgRQGPFADLZ/t
TOYzuIzZJFOcdKtEtrVkxZRGSkjZwKFKLUD6fzSjoC2M2EHktK/y5HsvxBxL4tKr
q1ffbyPQi+iBLYTZAXygvxj2vWyrvA+/w4nbt1fStCHTDhWjLWqFpV9nAoGDAKzA
HUu/IRl7OiUtW/dz36gzEJnaYtz4ZtJl0FG8RJiOe02lD8myqW2sVzYqMvKD0LGx
x9fdSKC1G+aZ/NWtqrQjb66Daf7b0ddDx+bfWTWJ2dOtZd8IL2rmQQJm+JogDi9i
huVYFicDNQGzi+nEKAzrZ1L/VxtiSiw/qw0IyOuVtz8CFjgPiPatvmWssQw2AuZ9
mFvAZ/8wal0=
-----END X9.42 DH PARAMETERS-----"""

    test_cli("gen_dl_group", ["--pbits=1043", "--qbits=174"], pem)

    dsa_grp = """-----BEGIN DSA PARAMETERS-----
MIIBHgKBgQCyP1vosC/axliM2hmJ9EOSdd1zBkuzMP25CYD8PFkRVrPLr1ClSUtn
eXTIsHToJ7d7sRwtidQGW9BrvUEyiAWE06W/wnLPxB3/g2/l/P2EhbNmNHAO7rV7
ZVz/uKR4Xcvzxg9uk5MpT1VsxA8H6VEwzefNF1Rya92rqGgBTNT3/wIVAL8IVgyt
8mRJqYXO3cJePyd2afjFAoGALscsvwAa7e2onFOTWI2CiOM6JKt4ufqKEDxHyRCd
FcNM20MrP33oocYid8wG6tQjXM8zfGpsdzQK9TU1/zt6eE8it63MlwWCIJas0VQg
LbnM8SOnSzf8REdPgGLVMAFnePphQRB+eeP71euIood/Za1fRPgVeiu+cqrfSb3f
ivM=
-----END DSA PARAMETERS-----"""

    test_cli("gen_dl_group", ["--type=dsa", "--pbits=1024"], dsa_grp)


def cli_key_tests(tmp_dir):

    pem = """-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg2A+I9q2+ZayxDDYC5n2Y
W8Bn/zBm4D3mwS5qMwADRDehRANCAATwnDFqsjXL9SD/Rr1Vy4pb79PswXdQNZBN
mlLtJ5JvZ0/p6zP3x+Y9yPIrAR8L/acG5ItSrAKXzzuqQQZMv4aN
-----END PRIVATE KEY-----"""

    priv_key = os.path.join(tmp_dir, 'priv.pem')
    pub_key = os.path.join(tmp_dir, 'pub.pem')
    pub_der_key = os.path.join(tmp_dir, 'pub.der')
    enc_pem = os.path.join(tmp_dir, 'priv_enc.pem')
    enc_der = os.path.join(tmp_dir, 'priv_enc.der')
    ca_cert = os.path.join(tmp_dir, 'ca.crt')
    crt_req = os.path.join(tmp_dir, 'crt.req')
    user_cert = os.path.join(tmp_dir, 'user.crt')

    test_cli("keygen", ["--algo=ECDSA", "--params=secp256k1"], pem)

    test_cli("keygen", ["--algo=ECDSA", "--params=secp256r1", "--output=" + priv_key], "")

    test_cli("pkcs8", "--pub-out --output=%s %s" % (pub_key, priv_key), "")
    test_cli("pkcs8", "--pub-out --der-out --output=%s %s" % (pub_der_key, priv_key), "")

    test_cli("pkcs8", "--pass-out=foof --cipher=AES-128/CBC --der-out --output=%s %s" % (enc_der, priv_key), "")
    test_cli("pkcs8", "--pass-out=foof --pbkdf=Scrypt --output=%s %s" % (enc_pem, priv_key), "")

    dec_pem = test_cli("pkcs8", ["--pass-in=foof", enc_pem], None)
    dec_der = test_cli("pkcs8", ["--pass-in=foof", enc_der], None)

    if dec_pem != dec_der:
        logging.error("Problem decrypting PKCS8 key")

    test_cli("fingerprint", ['--no-fsname', pub_key],
             "83:FC:67:87:30:C7:0C:9C:54:9A:E7:A1:FA:25:83:4C:77:A4:43:16:33:6D:47:3C:CE:4B:91:62:30:97:62:D4")

    test_cli("fingerprint", ['--no-fsname', pub_der_key],
             "83:FC:67:87:30:C7:0C:9C:54:9A:E7:A1:FA:25:83:4C:77:A4:43:16:33:6D:47:3C:CE:4B:91:62:30:97:62:D4")

    test_cli("fingerprint", ['--no-fsname', pub_key, pub_der_key],
             "83:FC:67:87:30:C7:0C:9C:54:9A:E7:A1:FA:25:83:4C:77:A4:43:16:33:6D:47:3C:CE:4B:91:62:30:97:62:D4\n"
             "83:FC:67:87:30:C7:0C:9C:54:9A:E7:A1:FA:25:83:4C:77:A4:43:16:33:6D:47:3C:CE:4B:91:62:30:97:62:D4")

    test_cli("fingerprint", [pub_der_key],
             pub_der_key +
             ": 83:FC:67:87:30:C7:0C:9C:54:9A:E7:A1:FA:25:83:4C:77:A4:43:16:33:6D:47:3C:CE:4B:91:62:30:97:62:D4")

    test_cli("fingerprint", ['-'],
             "83:FC:67:87:30:C7:0C:9C:54:9A:E7:A1:FA:25:83:4C:77:A4:43:16:33:6D:47:3C:CE:4B:91:62:30:97:62:D4",
             open(pub_key, 'rb').read().decode())

    valid_sig = "nI4mI1ec14Y7nYUWs2edysAVvkob0TWpmGh5rrYWDA+/W9Fj0ZM21qJw8qa3/avAOIVBO6hoMEVmfJYXlS+ReA=="

    test_cli("sign", "%s %s" % (priv_key, pub_key), valid_sig)

    test_cli("verify", [pub_key, pub_key, '-'],
             "Signature is valid", valid_sig)

    test_cli("verify", [pub_key, pub_key, '-'],
             "Signature is invalid",
             valid_sig.replace("G", "H"))

    test_cli("gen_self_signed",
             [priv_key, "CA", "--ca", "--country=VT",
              "--dns=ca.example", "--hash=SHA-384", "--output="+ca_cert],
             "")

    test_cli("cert_verify", ca_cert, "Certificate did not validate - Cannot establish trust")

    cert_info = test_cli("cert_info", ['--fingerprint', ca_cert], None)

    if cert_info.find('Subject: CN="CA",C="VT"') < 0:
        logging.error('Unexpected output for cert_info command %s', cert_info)
    if cert_info.find('Subject keyid: 69DD911C9EEE3400C67CBC3F3056CBE711BD56AF9495013F') < 0:
        logging.error('Unexpected output for cert_info command %s', cert_info)

    test_cli("gen_pkcs10", "%s User --output=%s" % (priv_key, crt_req))

    test_cli("sign_cert", "%s %s %s --output=%s" % (ca_cert, priv_key, crt_req, user_cert))

    test_cli("cert_verify", [user_cert, ca_cert],
             "Certificate passes validation checks")

    test_cli("cert_verify", user_cert,
             "Certificate did not validate - Certificate issuer not found")

def cli_xmss_sign_tests(tmp_dir):
    priv_key = os.path.join(tmp_dir, 'priv.pem')
    pub_key = os.path.join(tmp_dir, 'pub.pem')
    pub_key2 = os.path.join(tmp_dir, 'pub2.pem')
    msg = os.path.join(tmp_dir, 'input')
    sig1 = os.path.join(tmp_dir, 'sig1')
    sig2 = os.path.join(tmp_dir, 'sig2')
    root_crt = os.path.join(tmp_dir, 'root.crt')
    int_csr = os.path.join(tmp_dir, 'int.csr')
    int_crt = os.path.join(tmp_dir, 'int.crt')

    test_cli("rng", ['--output=%s' % (msg)], "")
    test_cli("hash", ["--no-fsname", msg], "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")

    test_cli("keygen", ["--algo=XMSS", "--output=%s" % (priv_key)], "")
    test_cli("hash", ["--no-fsname", priv_key], "1F040283F0D7D2156B06B7BE03FA5861035FF3BCC059671DB288162C04A94CED")

    test_cli("pkcs8", "--pub-out --output=%s %s" % (pub_key, priv_key), "")
    test_cli("fingerprint", ['--no-fsname', pub_key],
             "6F:C4:08:CB:C3:61:CC:49:8A:25:90:3B:2F:D4:4D:B8:7F:2F:27:06:8C:8F:01:E0:01:DB:42:1F:B4:09:09:D9")

    # verify the key is updated after each signature:
    test_cli("sign", [priv_key, msg, "--output=%s" % (sig1)], "")
    test_cli("verify", [pub_key, msg, sig1], "Signature is valid")
    test_cli("hash", ["--no-fsname", sig1], "9DEBA79CE9FDC4966D7BA7B05ABEC54E3C11BB1C2C2732F7658820F2CAE47646")
    test_cli("hash", ["--no-fsname", priv_key], "A71507087530C85E9CF971CF3A305890B07B51519C405A2B3D0037C64D5802B1")

    test_cli("sign", [priv_key, msg, "--output=%s" % (sig2)], "")
    test_cli("verify", [pub_key, msg, sig2], "Signature is valid")
    test_cli("hash", ["--no-fsname", sig2], "803EC5D6BECDFB9DC676EE2EDFEFE3D71EE924343A2ED9D2D7BFF0A9D97D704E")
    test_cli("hash", ["--no-fsname", priv_key], "D581F5BFDA65669A825165C7A9CF17D6D5C5DF349004BCB7416DCD1A5C0349A0")

    # private key updates, public key is unchanged:
    test_cli("pkcs8", "--pub-out --output=%s %s" % (pub_key2, priv_key), "")
    test_cli("fingerprint", ['--no-fsname', pub_key2],
             "6F:C4:08:CB:C3:61:CC:49:8A:25:90:3B:2F:D4:4D:B8:7F:2F:27:06:8C:8F:01:E0:01:DB:42:1F:B4:09:09:D9")

    # verify that key is updated when creating a self-signed certificate
    test_cli("gen_self_signed",
             [priv_key, "Root", "--ca", "--path-limit=2", "--output="+root_crt], "")
    test_cli("hash", ["--no-fsname", priv_key], "ACFD94CDF5D0674EE5489039CF70850A1FFF95480A94E8C6C6FD2BF006909D07")

    # verify that key is updated after signing a certificate request
    test_cli("gen_pkcs10", "%s Intermediate --ca --output=%s" % (priv_key, int_csr))
    test_cli("hash", ["--no-fsname", priv_key], "BE6F8F868DB495D95F73B50A370A218225253048E2F1C7C3E286568FDE203700")

    # verify that key is updated after issuing a certificate
    test_cli("sign_cert", "%s %s %s --output=%s" % (root_crt, priv_key, int_csr, int_crt))
    test_cli("hash", ["--no-fsname", priv_key], "8D3B736D8A708C342F9263163E0E3BAFE4132F74AE53A8EDF78074422CF80496")

    test_cli("cert_verify", "%s %s" % (int_crt, root_crt), "Certificate passes validation checks")

def cli_pbkdf_tune_tests(_tmp_dir):
    if not check_for_command("pbkdf_tune"):
        return

    expected = re.compile(r'For (default|[1-9][0-9]*) ms selected Scrypt\([0-9]+,[0-9]+,[0-9]+\) using [0-9]+ MiB')

    output = test_cli("pbkdf_tune", ["--tune-msec=1", "--check", "1", "10", "50", "default"], None).split('\n')

    for line in output:
        if expected.match(line) is None:
            logging.error("Unexpected line '%s'", line)

    expected_pbkdf2 = re.compile(r'For (default|[1-9][0-9]*) ms selected PBKDF2\(HMAC\(SHA-256\),[0-9]+\)')

    output = test_cli("pbkdf_tune", ["--algo=PBKDF2(SHA-256)", "--check", "1", "10", "50", "default"], None).split('\n')

    for line in output:
        if expected_pbkdf2.match(line) is None:
            logging.error("Unexpected line '%s'", line)

    expected_argon2 = re.compile(r'For (default|[1-9][0-9]*) ms selected Argon2id\([0-9]+,[0-9]+,[0-9]+\)')

    output = test_cli("pbkdf_tune", ["--algo=Argon2id", "--check", "1", "10", "50", "default"], None).split('\n')

    for line in output:
        if expected_argon2.match(line) is None:
            logging.error("Unexpected line '%s'", line)

def cli_psk_db_tests(tmp_dir):
    if not check_for_command("psk_get"):
        return

    psk_db = os.path.join(tmp_dir, 'psk.db')
    db_key1 = "909"*32
    db_key2 = "451"*32

    test_cli("psk_set", [psk_db, db_key1, "name", "F00FEE"], "")
    test_cli("psk_set", [psk_db, db_key2, "name", "C00FEE11"], "")
    test_cli("psk_set", [psk_db, db_key1, "name2", "50051029"], "")

    test_cli("psk_get", [psk_db, db_key1, "name"], "F00FEE")
    test_cli("psk_get", [psk_db, db_key2, "name"], "C00FEE11")

    test_cli("psk_list", [psk_db, db_key1], "name\nname2")
    test_cli("psk_list", [psk_db, db_key2], "name")

def cli_compress_tests(tmp_dir):

    if not check_for_command("compress"):
        return

    input_file = os.path.join(tmp_dir, 'input.txt')
    output_file = os.path.join(tmp_dir, 'input.txt.gz')

    with open(input_file, 'w', encoding='utf8') as f:
        f.write("hi there")
        f.close()

    test_cli("compress", input_file)

    if not os.access(output_file, os.R_OK):
        logging.error("Compression did not created expected output file")

    output_hdr = open(output_file, 'rb').read(2)

    if output_hdr[0] != 0x1F or output_hdr[1] != 0x8B:
        logging.error("Did not see expected gzip header")

    os.unlink(input_file)

    test_cli("decompress", output_file)

    if not os.access(input_file, os.R_OK):
        logging.error("Decompression did not created expected output file")

    recovered = open(input_file, encoding='utf8').read()
    if recovered != "hi there":
        logging.error("Decompression did not recover original input")

def cli_rng_tests(_tmp_dir):
    test_cli("rng", "10", "D80F88F6ADBE65ACB10C")
    test_cli("rng", "16", "D80F88F6ADBE65ACB10C3602E67D985B")
    test_cli("rng", "10 6", "D80F88F6ADBE65ACB10C\n1B119CC068AF")

    test_cli("rng", ['--format=base64', '10'], "2A+I9q2+ZayxDA==")
    test_cli("rng", ['--format=base58', '10'], "D93XRyVfxqs7oR")
    test_cli("rng", ['--format=base58check', '10'], "2NS1jYUq92TyGFVnhVLa")

    hex_10 = re.compile('[A-F0-9]{20}')

    for rng in ['system', 'auto', 'entropy']:
        output = test_cli("rng", ["10", '--%s' % (rng)], use_drbg=False)
        if output == "D80F88F6ADBE65ACB10C":
            logging.error('RNG produced DRBG output')
        if hex_10.match(output) is None:
            logging.error('Unexpected RNG output %s', output)

    has_rdrand = test_cli("cpuid", []).find(' rdrand ') > 0

    if has_rdrand:
        output = test_cli("rng", ["10", '--rdrand'], use_drbg=False)

        if output == "D80F88F6ADBE65ACB10C":
            logging.error('RDRAND produced DRBG output')
        if hex_10.match(output) is None:
            logging.error('Unexpected RNG output %s', output)

def cli_roughtime_check_tests(tmp_dir):
    if not check_for_command("roughtime_check"):
        return
    chain = os.path.join(tmp_dir, 'roughtime-chain')

    with open(chain, 'w', encoding='utf8') as f:
        f.write("""\
ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA
ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= uLeTON9D+2HqJMzK6sYWLNDEdtBl9t/9yw1cVAOm0/sONH5Oqdq9dVPkC9syjuWbglCiCPVF+FbOtcxCkrgMmA== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWOw1jl0uSiBEH9HE8/6r7zxoSc01f48vw+UzH8+VJoPelnvVJBj4lnH8uRLh5Aw0i4Du7XM1dp2u0r/I5PzhMQoDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AUBo+tEqPBQC47l77to7ESFTVhlw1SC74P5ssx6gpuJ6eP+1916GuUiySGE/x3Fp0c3otUGAdsRQou5p9PDTeane/YEeVq4/8AgAAAEAAAABTSUcAREVMRe5T1ml8wHyWAcEtHP/U5Rg/jFXTEXOSglngSa4aI/CECVdy4ZNWeP6vv+2//ZW7lQsrWo7ZkXpvm9BdBONRSQIDAAAAIAAAACgAAABQVUJLTUlOVE1BWFQpXlenV0OfVisvp9jDHXLw8vymZVK9Pgw9k6Edf8ZEhUgSGEc5jwUASHLvZE2PBQAAAAAA
ed25519 etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ= U53wX99JzZwy4BXa9C6R04bPu4yqFB5w5/wTgG8Mw5wm+VLrY70ECxJ9ZHnpdHVHaLEU3aeLnQFZyZPRAEOCyw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWMh3mPWCCbOlX8xDWbU9qdfKoReJX/XLsivom8bJJYmcC7T03tyXrtWUheEJweHtg4qMgSyifQS1MjHJSy1jPAsDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8Akxw/tEqPBQBfOsOuciR7jiAW5itQ39y8yVr/ZJmgMwvTjqaU4/wA05ZqG4RqoLdvDXh5bCNySL6LrrnBNSAHwn5COt0CItNuAgAAAEAAAABTSUcAREVMRVP3BIOzsZmuxqMi+ScIBPyKtzFfK7ZlPFNP0JrNwln2QYtAcQFIKywDdNAAL+n8i3dz1p99K50FJjCkCl2J6AMDAAAAIAAAACgAAABQVUJLTUlOVE1BWFQKC/kZVdjiNT2NCSGfnpot4eqipyMFsyMjiIQmqqqXqQCAa245jwUAAGCgA56PBQAAAAAA
ed25519 AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE= IcZcXFuaLKYYhWcK3sT/6PrVeXMmabCRbf9hvVfkMkqEW1PFL++ZnHJ1/m+G8azITxvktwsfP1YAOOxWdbf9XQ== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWL5DAl8GPNUQ/mSXl0tI4N9yZAO+PiXTodJOTDL+WU/x26iqgyyQRikSSocRMzAEVLDGasdyW19mVC6H/6vfXggDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8Av/JAtEqPBQBIP346SHhCdDfughzeH+uYSbxngDYxqHzBDtZt0obUKrzxfRWzD1oR61B1reLvoPVCKSfzEngi/g1NSQjTrzNMAgAAAEAAAABTSUcAREVMRTQLLplQv0rN4p77Bo59qT8bbquV6MKSwILI/Tw2LLGo9noaZegUFmM+rNu1d1AVOEVQ01j6/2xDmBvp0d6MZgEDAAAAIAAAACgAAABQVUJLTUlOVE1BWFS4a1dYoIB5u/zkbR3sIteuhVrQkszzj+Gng9ywo6O9VgAAAAAAAAAA//////////8AAAAA
ed25519 cj8GsiNlRkqiDElAeNMSBBMwrAl15hYPgX50+GWX/lA= Tsy82BBU2xxVqNe1ip11OyEGoKWhKoSggWjBmDTSBmKbTs7bPPCEidYc5TQ23sQUWe62G35fQOVU28q+Eq5uhQ== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWDAmi7zgXAqLgQXVfbjeqnUZRiXCZI64QIoAKFL83CQHbyXgB4cNwHfQ9mSg0hYxTp1M8QxOuzusnUpk05DIRwwDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AcOBCtEqPBQBhsr1mKOxxCf4VDFzAtYB4Nhs332AN1LrJU/8+VqktzfPd2R7awJHEVEWugvSvOrr+9d332mQObAkYfKfDtbSFAgAAAEAAAABTSUcAREVMRUjnhDvkIjFzTEYtgHOfMpRHtnNZj4P31RFtapkwzGjOtc93pYDd7zqQCw2AVcfbSnPqa8k26z96Q9fVRzq0pw8DAAAAIAAAACgAAABQVUJLTUlOVE1BWFR7qp2oerjpbN8Y23nUGARIlsgkodW4owH29ZKhxDMn8AAAAAAAAAAA//////////8AAAAA
""")

    test_cli("roughtime_check", chain, """\
1: UTC 2019-08-04T13:38:17 (+-1000000us)
  2: UTC 2019-08-04T13:38:17 (+-1000000us)
  3: UTC 2019-08-04T13:38:17 (+-1000000us)
  4: UTC 2019-08-04T13:38:18 (+-1000000us)
  5: UTC 2019-08-04T13:38:18 (+-1000000us)""")

    with open(chain, 'w', encoding='utf8') as f:
        f.write("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA")
    test_cli("roughtime_check", [chain, "--raw-time"], "1: UTC 1564925897781286 (+-1000000us)")

    with open(chain, 'w', encoding='utf8') as f:
        f.write("ed25519 cbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA")
    test_cli("roughtime_check", chain, expected_stderr='Error: Roughtime: Invalid signature or public key')

def cli_roughtime_tests(tmp_dir):
    if not check_for_command("roughtime"):
        return

    server_port = port_for('roughtime')
    chain_file = os.path.join(tmp_dir, 'roughtime-chain')
    ecosystem = os.path.join(tmp_dir, 'ecosystem')

    def run_udp_server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ('127.0.0.1', server_port)
        sock.bind(server_address)

        while True:
            data, address = sock.recvfrom(4096)

            if data:
                if data != base64.b64decode(server_request):
                    logging.error("unexpected request")

                sock.sendto(base64.b64decode(server_response), address)

    udp_thread = threading.Thread(target=run_udp_server)
    udp_thread.daemon = True
    udp_thread.start()

    chain = [
        """\
ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= 2A+I9q2+ZayxDDYC5n2YW8Bn/zBm4D3mwS5qMwADRDcbFpBcf3yPOyeZiqpLBTkxo8GT8zMQFeApv4ScffjC8A== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWDwlo/AkUnTrecAW4Ci5Tkh3KOqs6R7KLTsFtq16RXN5F7G5ckGv11UtzHoZTbKbEk03a6ogAOK54Q2CI/7XGA8DAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AWDLihlaSBQAoq/5gEjRCrhfH16X2GYjQJSG/CgSuGhYeCsrw7XkphLI3cxw2unJRDW8DAJrYqEGaW0NPKZk7bbpPjU/Q6Es1AgAAAEAAAABTSUcAREVMRUJbs67Sb5Wx/jzWyT1PhWR0c4kg59tjSGofo8R3eHzcA9CGwavuRdxOArhVWWODG99gYgfmjcRLgt9/jH+99w4DAAAAIAAAACgAAABQVUJLTUlOVE1BWFRXRfQ1RHLWGOgqABUTYfVBDZrv3OL2nPLYve9ldfNVLOjdPVFFkgUA6D0Vb1mSBQAAAAAA
""",
        """\
ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= 2A+I9q2+ZayxDDYC5n2YW8Bn/zBm4D3mwS5qMwADRDcbFpBcf3yPOyeZiqpLBTkxo8GT8zMQFeApv4ScffjC8A== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWDwlo/AkUnTrecAW4Ci5Tkh3KOqs6R7KLTsFtq16RXN5F7G5ckGv11UtzHoZTbKbEk03a6ogAOK54Q2CI/7XGA8DAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AWDLihlaSBQAoq/5gEjRCrhfH16X2GYjQJSG/CgSuGhYeCsrw7XkphLI3cxw2unJRDW8DAJrYqEGaW0NPKZk7bbpPjU/Q6Es1AgAAAEAAAABTSUcAREVMRUJbs67Sb5Wx/jzWyT1PhWR0c4kg59tjSGofo8R3eHzcA9CGwavuRdxOArhVWWODG99gYgfmjcRLgt9/jH+99w4DAAAAIAAAACgAAABQVUJLTUlOVE1BWFRXRfQ1RHLWGOgqABUTYfVBDZrv3OL2nPLYve9ldfNVLOjdPVFFkgUA6D0Vb1mSBQAAAAAA
ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= 2A+I9q2+ZayxDDYC5n2YW8Bn/zBm4D3mwS5qMwADRDcbFpBcf3yPOyeZiqpLBTkxo8GT8zMQFeApv4ScffjC8A== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWHH5Ofs4HciIFXjE9egjDbistJptoMXIC7ugCgHhI4NPJqfYY256NpULXKc9c30ul7oHXQyKLfGd84mIAxC3UwQDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AuOoUh1aSBQANeC4gGGG3a23PpmF+y6CrUS9VWjyj0Ydpl2tMVDLaK2vd5QtYKKJ3UOyprGKk0D/aPn4E3Bk2rE3BKBZRXM1AAgAAAEAAAABTSUcAREVMRci9uvioJssgd8txxFlqz9RqPx+YLVMkHmm24fMUtYGWF/nhkoEYVGT7O+tXSfHHY/KHcUZjVaZpEt/tmXlXBAUDAAAAIAAAACgAAABQVUJLTUlOVE1BWFSxhKhavdriTvCAtNVcK5yr0cAbsWp2MsrwUV5YTc+7V0CsaLZSkgUAQAxA1GaSBQAAAAAA
""",
        """\
ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= SbWKPilWYrt+1vgFU3jlxGNOH6I/1npX8wl+KoraN3S6VDsyM6EfCV+JPEK8BsNoM2VIpMcSdjcVna/GwXwZkg== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWHH5Ofs4HciIFXjE9egjDbistJptoMXIC7ugCgHhI4NPJqfYY256NpULXKc9c30ul7oHXQyKLfGd84mIAxC3UwQDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AuOoUh1aSBQANeC4gGGG3a23PpmF+y6CrUS9VWjyj0Ydpl2tMVDLaK2vd5QtYKKJ3UOyprGKk0D/aPn4E3Bk2rE3BKBZRXM1AAgAAAEAAAABTSUcAREVMRci9uvioJssgd8txxFlqz9RqPx+YLVMkHmm24fMUtYGWF/nhkoEYVGT7O+tXSfHHY/KHcUZjVaZpEt/tmXlXBAUDAAAAIAAAACgAAABQVUJLTUlOVE1BWFSxhKhavdriTvCAtNVcK5yr0cAbsWp2MsrwUV5YTc+7V0CsaLZSkgUAQAxA1GaSBQAAAAAA
ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= 2A+I9q2+ZayxDDYC5n2YW8Bn/zBm4D3mwS5qMwADRDcbFpBcf3yPOyeZiqpLBTkxo8GT8zMQFeApv4ScffjC8A== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWN5Y0b2irPS1JgqJFQMciPg4aWd9qj1ZqcJc5bGXe1m4ZdAXa5OIhXa0+680MgpyhEHhqYJDIwH1XRa1OZx5YAUDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AgBW3iFaSBQD9WI+Qr6NOZsDmP0PsnCo66mstM3ac5ZON+I+ZeEK8lZWBASvsD2JIfq3v4d1QH5g4STs3wOazQPc25Puy659ZAgAAAEAAAABTSUcAREVMRUJbs67Sb5Wx/jzWyT1PhWR0c4kg59tjSGofo8R3eHzcA9CGwavuRdxOArhVWWODG99gYgfmjcRLgt9/jH+99w4DAAAAIAAAACgAAABQVUJLTUlOVE1BWFRXRfQ1RHLWGOgqABUTYfVBDZrv3OL2nPLYve9ldfNVLOjdPVFFkgUA6D0Vb1mSBQAAAAAA
""",
    ]
    request = [
        "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",
    ]
    response = [
        "BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWDwlo/AkUnTrecAW4Ci5Tkh3KOqs6R7KLTsFtq16RXN5F7G5ckGv11UtzHoZTbKbEk03a6ogAOK54Q2CI/7XGA8DAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AWDLihlaSBQAoq/5gEjRCrhfH16X2GYjQJSG/CgSuGhYeCsrw7XkphLI3cxw2unJRDW8DAJrYqEGaW0NPKZk7bbpPjU/Q6Es1AgAAAEAAAABTSUcAREVMRUJbs67Sb5Wx/jzWyT1PhWR0c4kg59tjSGofo8R3eHzcA9CGwavuRdxOArhVWWODG99gYgfmjcRLgt9/jH+99w4DAAAAIAAAACgAAABQVUJLTUlOVE1BWFRXRfQ1RHLWGOgqABUTYfVBDZrv3OL2nPLYve9ldfNVLOjdPVFFkgUA6D0Vb1mSBQAAAAAA",
        "BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWHH5Ofs4HciIFXjE9egjDbistJptoMXIC7ugCgHhI4NPJqfYY256NpULXKc9c30ul7oHXQyKLfGd84mIAxC3UwQDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AuOoUh1aSBQANeC4gGGG3a23PpmF+y6CrUS9VWjyj0Ydpl2tMVDLaK2vd5QtYKKJ3UOyprGKk0D/aPn4E3Bk2rE3BKBZRXM1AAgAAAEAAAABTSUcAREVMRci9uvioJssgd8txxFlqz9RqPx+YLVMkHmm24fMUtYGWF/nhkoEYVGT7O+tXSfHHY/KHcUZjVaZpEt/tmXlXBAUDAAAAIAAAACgAAABQVUJLTUlOVE1BWFSxhKhavdriTvCAtNVcK5yr0cAbsWp2MsrwUV5YTc+7V0CsaLZSkgUAQAxA1GaSBQAAAAAA",
        "BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWN5Y0b2irPS1JgqJFQMciPg4aWd9qj1ZqcJc5bGXe1m4ZdAXa5OIhXa0+680MgpyhEHhqYJDIwH1XRa1OZx5YAUDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AgBW3iFaSBQD9WI+Qr6NOZsDmP0PsnCo66mstM3ac5ZON+I+ZeEK8lZWBASvsD2JIfq3v4d1QH5g4STs3wOazQPc25Puy659ZAgAAAEAAAABTSUcAREVMRUJbs67Sb5Wx/jzWyT1PhWR0c4kg59tjSGofo8R3eHzcA9CGwavuRdxOArhVWWODG99gYgfmjcRLgt9/jH+99w4DAAAAIAAAACgAAABQVUJLTUlOVE1BWFRXRfQ1RHLWGOgqABUTYfVBDZrv3OL2nPLYve9ldfNVLOjdPVFFkgUA6D0Vb1mSBQAAAAAA",
    ]

    server_request = request[0]
    server_response = response[0]
    test_cli("roughtime", [], expected_stderr='Please specify either --servers-file or --host and --pubkey')

    with open(ecosystem, 'w', encoding='utf8') as f:
        f.write("Cloudflare-Roughtime ed25519 gD63hSj4ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= udp 127.0.0.1:" + str(server_port))

    test_cli("roughtime", [
        "--check-local-clock=0",
        "--chain-file=",
        "--servers-file=" + ecosystem]
             , expected_stderr='ERROR: Public key does not match!')

    with open(ecosystem, 'w', encoding='utf8') as f:
        f.write("Cloudflare-Roughtime ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= udp 127.0.0.1:" + str(server_port))

    test_cli("roughtime", [
        "--chain-file=",
        "--servers-file=" + ecosystem]
             , expected_stderr='ERROR: Local clock mismatch')

    test_cli("roughtime", [
        "--check-local-clock=0",
        "--chain-file=" + chain_file,
        "--servers-file=" + ecosystem]
             , "Cloudflare-Roughtime     : UTC 2019-09-12T08:00:11 (+-1000000us)")

    with open(chain_file, 'r', encoding='utf8') as f:
        read_data = f.read()
    if read_data != chain[0]:
        logging.error("unexpected chain")

    server_request = request[1]
    server_response = response[1]
    test_cli("roughtime", [
        "--check-local-clock=0",
        "--chain-file=" + chain_file,
        "--host=127.0.0.1:" + str(server_port),
        "--pubkey=gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=",
        "--raw-time"]
             , "UTC 1568275214691000 (+-1000000us)")

    with open(chain_file, 'r', encoding='utf8') as f:
        read_data = f.read()
    if read_data != chain[1]:
        logging.error("unexpected chain")

    server_request = request[2]
    server_response = response[2]
    test_cli("roughtime", [
        "--check-local-clock=0",
        "--chain-file=" + chain_file,
        "--host=127.0.0.1:" + str(server_port),
        "--pubkey=gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=",
        "--max-chain-size=2"]
             , "UTC 2019-09-12T08:00:42 (+-1000000us)")

    with open(chain_file, 'r', encoding='utf8') as f:
        read_data = f.read()
    if read_data != chain[2]:
        logging.error("unexpected chain")

def cli_zfec_tests(tmp_dir):
    input_file = os.path.join(tmp_dir, 'input.bin')

    exp_hash = "B49BCD978052C2C05A2D9ACE9863D150E3FA5765FCDF91AC47B5EAD54BFEE24E"

    test_cli("rng", ["4096", "--output=%s" % (input_file)], "")
    test_cli("hash", ["--no-fsname", input_file], exp_hash)
    prefix = "test"
    k = 3
    n = 5

    test_cli("fec_encode", ["--output-dir=%s" % (tmp_dir),
                            "--prefix=%s" % (prefix),
                            str(k), str(n), input_file])

    info_re = re.compile('FEC share [0-9]/%d with %d needed for recovery' % (n, k))

    share_files = []
    for share in range(1, n + 1):
        expected_share = os.path.join(tmp_dir, '%s.%d_%d.fec' % (prefix, share, n))
        share_files.append(expected_share)
        info_out = test_cli("fec_info", expected_share)
        if info_re.match(info_out) is None:
            logging.error("Unexpected output for fec_info")

    k_shares = n - k

    # Insufficient shares:
    test_cli("fec_decode", share_files[(k_shares + 1):], None, None,
             "At least %d shares are required for recovery" % (k))

    output_file = os.path.join(tmp_dir, 'output.bin')
    test_cli("fec_decode", share_files[k_shares:] + ["--output=%s" % (output_file)])
    test_cli("hash", ["--no-fsname", output_file], exp_hash)

def cli_pk_workfactor_tests(_tmp_dir):
    test_cli("pk_workfactor", "1024", "80")
    test_cli("pk_workfactor", "2048", "111")
    test_cli("pk_workfactor", ["--type=rsa", "512"], "58")
    test_cli("pk_workfactor", ["--type=dl", "512"], "58")
    test_cli("pk_workfactor", ["--type=dl_exp", "512"], "192")

def cli_dl_group_info_tests(_tmp_dir):

    dl_output = re.compile('(P|G) = [A-F0-9]+')

    for bits in [1024, 1536, 2048, 3072, 4096, 6144, 8192]:
        output = test_cli("dl_group_info", "modp/ietf/%d" % (bits))
        lines = output.split('\n')

        if len(lines) != 2:
            logging.error('Unexpected output from dl_group_info')

        for l in lines:
            if not dl_output.match(l):
                logging.error('Unexpected output from dl_group_info')



def cli_ec_group_info_tests(_tmp_dir):

    secp256r1_info = """P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"""

    secp256r1_pem = """-----BEGIN EC PARAMETERS-----
MIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP//////////
/////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6
k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9
gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA
/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQE=
-----END EC PARAMETERS-----"""

    test_cli("ec_group_info", "secp256r1", secp256r1_info)
    test_cli("ec_group_info", "--pem secp256r1", secp256r1_pem)

def cli_cpuid_tests(_tmp_dir):
    def read_flags(cli_output):
        if not cpuid_output.startswith('CPUID flags:'):
            logging.error('Unexpected cpuid output "%s"', cpuid_output)

        return cli_output[13:].split(' ') if cli_output[13:] != '' else []

    cpuid_output = test_cli("cpuid", [])
    flag_re = re.compile('[a-z0-9_]+')
    flags = read_flags(cpuid_output)
    for flag in flags:
        if flag != '' and flag_re.match(flag) is None:
            logging.error('Unexpected CPUID flag name "%s"', flag)

        env = {'BOTAN_CLEAR_CPUID': flag}
        cpuid_output = test_cli("cpuid", [], None, None, None, True, env)
        mod_flags = read_flags(cpuid_output)

        for f in mod_flags:
            if f == flag:
                logging.error('Clearing CPUID %s did not disable it', flag)
            if f not in flags:
                logging.error('Clearing CPUID %s caused flag %s to appear', flag, f)

def cli_cc_enc_tests(_tmp_dir):
    test_cli("cc_encrypt", ["8028028028028029", "pass"], "4308989841607208")
    test_cli("cc_decrypt", ["4308989841607208", "pass"], "8028028028028027")

def cli_cert_issuance_tests(tmp_dir, algos=None):
    root_key = os.path.join(tmp_dir, 'root.key')
    root_crt = os.path.join(tmp_dir, 'root.crt')
    int_key = os.path.join(tmp_dir, 'int.key')
    int_crt = os.path.join(tmp_dir, 'int.crt')
    int_csr = os.path.join(tmp_dir, 'int.csr')
    leaf_key = os.path.join(tmp_dir, 'leaf.key')
    leaf_crt = os.path.join(tmp_dir, 'leaf.crt')
    leaf_csr = os.path.join(tmp_dir, 'leaf.csr')

    if algos is None:
        algos = [("RSA", "2048"),("RSA", "2048"),("RSA", "2048")]

    test_cli("keygen", ["--algo=%s" % algos[0][0], "--params=%s" % algos[0][1], "--output=" + root_key], "")
    test_cli("keygen", ["--algo=%s" % algos[1][0], "--params=%s" % algos[1][1], "--output=" + int_key], "")
    test_cli("keygen", ["--algo=%s" % algos[2][0], "--params=%s" % algos[2][1], "--output=" + leaf_key], "")

    test_cli("gen_self_signed",
             [root_key, "Root", "--ca", "--path-limit=2", "--output="+root_crt], "")

    test_cli("gen_pkcs10", "%s Intermediate --ca --output=%s" % (int_key, int_csr))
    test_cli("sign_cert", "%s %s %s --output=%s" % (root_crt, root_key, int_csr, int_crt))

    test_cli("gen_pkcs10", "%s Leaf --output=%s" % (leaf_key, leaf_csr))
    test_cli("sign_cert", "%s %s %s --output=%s" % (int_crt, int_key, leaf_csr, leaf_crt))

    test_cli("cert_verify", "%s %s %s" % (leaf_crt, int_crt, root_crt), "Certificate passes validation checks")

def cli_cert_issuance_alternative_algos_tests(tmp_dir):
    for i, algo in enumerate([[("Dilithium", "Dilithium-8x7-AES-r3"), ("Dilithium", "Dilithium-8x7-AES-r3"), ("Dilithium", "Dilithium-8x7-AES-r3")],
                              [("ECDSA",     "secp256r1"),            ("ECDSA",     "secp384r1"),            ("ECDSA",     "secp256r1")],
                              [("Dilithium", "Dilithium-6x5-r3"),     ("ECDSA",     "secp256r1"),            ("RSA",       "2048")]]):
        sub_tmp_dir = os.path.join(tmp_dir, str(i))
        os.mkdir(sub_tmp_dir)
        cli_cert_issuance_tests(sub_tmp_dir, algo)

def cli_marvin_tests(tmp_dir):
    if not check_for_command("marvin_test"):
        return

    rsa_key = os.path.join(tmp_dir, 'rsa.pem')
    data_dir = os.path.join(tmp_dir, 'testcases')

    test_cli("keygen", ["--algo=RSA", "--params=1024", "--output=" + rsa_key], "")

    test_inputs = 4
    runs = 32

    # There is currently no way in CLI to do an RSA encryption with PKCS1 v1.5
    # so for now just create some random (certainly invalid) ciphertexts
    os.mkdir(data_dir)

    for i in range(test_inputs):
        output_file = os.path.join(data_dir, "invalid%d" % i)
        ctext = bytes([i] * 128)

        with open(output_file, 'bw') as out:
            out.write(ctext)

    output = test_cli("marvin_test", [rsa_key, data_dir, "--runs=%d" % (runs)])

    first_line = True
    total_lines = 0
    for line in output.split('\n'):
        res = line.split(',')

        if len(res) != test_inputs:
            logging.error("Unexpected output from MARVIN test: %s", line)

        if not first_line:
            try:
                for r in res:
                    float(r)
            except ValueError:
                logging.error("Unexpected output from MARVIN test: %s", line)

        first_line = False
        total_lines += 1

    if total_lines != runs + 1:
        logging.error("Unexpected number of lines from MARVIN test")

def cli_timing_test_tests(_tmp_dir):

    timing_tests = ["bleichenbacher", "manger",
                    "ecdsa", "ecc_mul", "inverse_mod", "pow_mod",
                    "lucky13sec3", "lucky13sec4sha1",
                    "lucky13sec4sha256", "lucky13sec4sha384"]

    output_re = re.compile('[0-9]+;[0-9];[0-9]+')

    for suite in timing_tests:
        output = test_cli("timing_test", [suite, "--measurement-runs=16", "--warmup-runs=3", "--test-data-dir=%s" % TEST_DATA_DIR], None).split('\n')

        for line in output:
            if output_re.match(line) is None:
                logging.error("Unexpected output in timing_test %s: %s", suite, line)

def cli_tls_ciphersuite_tests(_tmp_dir):
    policies = ['default', 'suiteb_128', 'suiteb_192', 'strict', 'all']

    versions = ['tls1.2']

    ciphersuite_re = re.compile('^[A-Z0-9_]+$')

    for policy in policies:
        for version in versions:

            if version != 'tls1.2' and policy != 'all':
                continue

            output = test_cli("tls_ciphers", ["--version=" + version, "--policy=" + policy], None).split('\n')

            for line in output:
                if ciphersuite_re.match(line) is None:
                    logging.error("Unexpected ciphersuite line %s", line)

def cli_asn1_tests(_tmp_dir):
    input_pem = """-----BEGIN BLOB-----
MCACAQUTBnN0cmluZzEGAQH/AgFjBAUAAAAAAAMEAP///w==
-----END BLOB------
"""

    expected = """d= 0, l=  32: SEQUENCE
  d= 1, l=   1:  INTEGER                                    5
  d= 1, l=   6:  PRINTABLE STRING                           string
  d= 1, l=   6:  SET
  d= 2, l=   1:   BOOLEAN                                   true
  d= 2, l=   1:   INTEGER                                   99
  d= 1, l=   5:  OCTET STRING                               0000000000
  d= 1, l=   4:  BIT STRING                                 FFFFFF"""

    test_cli("asn1print", "--pem -", expected, input_pem)

    test_cli("oid_info", "RSA", "The string 'RSA' is associated with OID 1.2.840.113549.1.1.1")
    test_cli("oid_info", "1.2.840.113549.1.1.1", "OID 1.2.840.113549.1.1.1 is associated with RSA")
    test_cli("oid_info", "1.2.3.4", "OID 1.2.3.4 is not recognized")

def cli_tls_socket_tests(tmp_dir):
    if not run_socket_tests() or not check_for_command("tls_client") or not check_for_command("tls_server"):
        return

    psk = "FEEDFACECAFEBEEF"
    psk_identity = "test-psk"

    class TestConfig:
        def __init__(self, name, protocol_version, policy, **kwargs):
            self.name = name
            self.protocol_version = protocol_version
            self.policy = policy
            self.stdout_regex = kwargs.get("stdout_regex")
            self.expect_error = kwargs.get("expect_error", False)
            self.psk = kwargs.get("psk")
            self.psk_identity = kwargs.get("psk_identity")

    configs = [
        # Explicitly testing x448-based key exchange against ourselves, as Bogo test
        # don't cover that. Better than nothing...
        TestConfig("x448", "1.2", "allow_tls12=true\nallow_tls13=false\nkey_exchange_groups=x448"),
        TestConfig("x448", "1.3", "allow_tls12=false\nallow_tls13=true\nkey_exchange_groups=x448"),

        # Regression test: TLS 1.3 server hit an assertion when no certificate
        #                  chain was found. Here, we provoke this by requiring
        #                  an RSA-based certificate (server uses ECDSA).
        TestConfig("No server cert", "1.3", "allow_tls12=false\nallow_tls13=true\nsignature_methods=RSA\n",
                   stdout_regex='Alert: handshake_failure', expect_error=True),

        TestConfig("TLS 1.3", "1.3", "allow_tls12=false\nallow_tls13=true\n"),
        TestConfig("TLS 1.2", "1.2", "allow_tls12=true\nallow_tls13=false\n"),

        # At the moment, TLS 1.2 does not implement record_size_limit.
        # Therefore, clients can offer it only with TLS 1.2 being disabled.
        # Otherwise, a server negotiating TLS 1.2 and using the record_size_limit
        # would not work for us.
        #
        # TODO: Remove this crutch after implementing record_size_limit for TLS 1.2
        #       and extend the test to use it for both TLS 1.2 and 1.3.
        TestConfig("Record size limit", "1.3", "allow_tls12=false\nallow_tls13=true\nrecord_size_limit=64\n"),

        TestConfig("PSK TLS 1.2", "1.2", "allow_tls12=true\nallow_tls13=false\nkey_exchange_methods=ECDHE_PSK\n",
                   psk=psk, psk_identity=psk_identity,
                   stdout_regex=f'Handshake complete, TLS v1\\.2.*\nUtilized PSK identity: {psk_identity}.*'),
        TestConfig("PSK TLS 1.3", "1.3", "allow_tls12=false\nallow_tls13=true\nkey_exchange_methods=ECDHE_PSK\n",
                   psk=psk, psk_identity=psk_identity,
                   stdout_regex=f'Handshake complete, TLS v1\\.3.*\nUtilized PSK identity: {psk_identity}.*'),

        TestConfig("Kyber KEM", "1.3", "allow_tls12=false\nallow_tls13=true\nkey_exchange_groups=Kyber-512-r3"),
        TestConfig("Hybrid PQ/T", "1.3", "allow_tls12=false\nallow_tls13=true\nkey_exchange_groups=x25519/Kyber-512-r3"),
    ]

    class TestServer(AsyncTestProcess):
        def __init__(self, tmp_dir, port, psk, psk_identity, clients=0):
            super().__init__("Server")
            self.port = port
            self.psk = psk
            self.psk_identity = psk_identity
            self.clients = clients

            self.cert_suite = ServerCertificateSuite(tmp_dir, "secp256r1", "SHA-384")
            self.policy = os.path.join(tmp_dir, 'test_server_policy.txt')

            with open(self.policy, 'w', encoding='utf8') as f:
                f.write('key_exchange_methods = ECDH DH ECDHE_PSK\n')
                f.write("key_exchange_groups = x25519 x448 secp256r1 ffdhe/ietf/2048 Kyber-512-r3 x25519/Kyber-512-r3")

        @property
        def ca_cert(self):
            return self.cert_suite.ca_cert

        async def __aenter__(self):
            server_cmd = [CLI_PATH, "tls_server", f"--max-clients={self.clients}",
                          f"--port={self.port}", f"--policy={self.policy}",
                          f"--psk={self.psk}", f"--psk-identity={self.psk_identity}",
                          self.cert_suite.cert, self.cert_suite.private_key]

            await self._launch(server_cmd, b'Listening for new connections')

            return self

        async def __aexit__(self, *_):
            await self._finalize()

    class TestClient(AsyncTestProcess):
        client_message = b'Client message %d with extra stuff to test record_size_limit: %s\n' % (random.randint(0, 2**128), b'oO' * 64)

        def __init__(self, tmp_dir, server_port, ca, config):
            super().__init__("Client")
            self.tmp_dir = tmp_dir
            self.port = server_port
            self.ca = ca
            self.policy = os.path.join(tmp_dir, 'test_client_policy.txt')
            self.config = config

            with open(self.policy, 'w', encoding='utf8') as f:
                f.write(self.config.policy)

        async def perform_message_ping_pong(self):
            # write the test message
            await self._write_to_stdin(TestClient.client_message)

            # expect the server to echo the test message, but don't
            # close our stdin pipe to the client, yet
            await self._read_stdout_until(TestClient.client_message)

            # close the client and expect to read stdout until EOF
            retcode = await self._close_stdin_read_stdout_to_eof_and_wait_for_termination()

            if retcode != 0:
                raise Exception(f'Client failed with error ({self.config.name}): {retcode}')
            self._check_stdout_regex()

        async def expect_handshake_error(self):
            retcode = await self._close_stdin_read_stdout_to_eof_and_wait_for_termination()
            if retcode == 0:
                raise Exception(f"Expected an error, but tls_client finished with success ({self.config.name})")
            self._check_stdout_regex()

        def _check_stdout_regex(self):
            if self.config.stdout_regex:
                match = re.search(self.config.stdout_regex, self.stdout)
                if not match:
                    raise Exception(f"Client log did not match expected regex ({self.config.name}): {self.config.stdout_regex}")

        async def __aenter__(self):
            client_cmd = [CLI_PATH, "tls_client", 'localhost', f'--port={self.port}', f'--trusted-cas={self.ca}',
                          f'--tls-version={self.config.protocol_version}', f'--policy={self.policy}']
            if self.config.psk:
                client_cmd += [f'--psk={self.config.psk}', f'--psk-identity={self.config.psk_identity}']

            await self._launch(client_cmd, b'Handshake complete' if not self.config.expect_error else None)

            return self

        async def __aexit__(self, *_):
            await self._finalize()

    async def run_async_test():
        async with TestServer(tmp_dir, port_for('tls_server'), psk, psk_identity, len(configs)) as server:
            errors = 0
            for tls_config in configs:
                logging.debug("Running test for %s in TLS %s mode", tls_config.name, tls_config.protocol_version)
                async with TestClient(tmp_dir, server.port, server.ca_cert, tls_config) as client:
                    try:
                        if tls_config.expect_error:
                            await client.expect_handshake_error()
                        else:
                            await client.perform_message_ping_pong()
                        client.all_clear()
                    except Exception as e:
                        logging.error("Test failed for %s: %s", tls_config.name, e)

            if not errors:
                server.all_clear()

    asyncio.run(run_async_test())

def cli_tls_online_pqc_hybrid_tests(tmp_dir):
    if not run_socket_tests() or not run_online_tests() or not check_for_command("tls_client"):
        return

    class TestConfig:
        def __init__(self, host, kex_algo, port=443, ca=None):
            self.host = host
            self.kex_algo = kex_algo
            self.port = port
            self.ca = ca

            self.policy_file = None
            self.ca_file = None

        def setup(self, tmp_dir):
            self.policy_file = tempfile.NamedTemporaryFile(dir=tmp_dir, mode="w+", encoding="utf-8")
            self.policy_file.write('\n'.join(["allow_tls13 = true",
                                   "allow_tls12 = false",
                                   "key_exchange_methods = HYBRID KEM",
                                   f"key_exchange_groups = {self.kex_algo}"]))
            self.policy_file.flush()

            if self.ca:
                self.ca_file =  tempfile.NamedTemporaryFile(dir=tmp_dir, mode="w+", encoding="utf-8")
                self.ca_file.write(self.ca)
                self.ca_file.flush()

        def run(self):
            cmd_options = []
            if self.ca_file:
                cmd_options += [f"--trusted-cas={self.ca_file.name}"]
            if self.port:
                cmd_options += [f"--port={self.port}"]
            cmd_options += [f"--policy={self.policy_file.name}"]
            cmd_options += [self.host]
            return test_cli("tls_client", cmd_options, cmd_input="", timeout=5)

    def get_oqs_resource(resource):
        try:
            conn = HTTPSConnection("test.openquantumsafe.org")
            conn.request("GET", resource)
            resp = conn.getresponse()
            if resp.status != 200:
                return None
            return resp.read().decode("utf-8")
        except Exception:
            return None

    def get_oqs_ports():
        try:
            return json.loads(get_oqs_resource("/assignments.json"))['ecdsap256']
        except Exception:
            return None

    def get_oqs_rootca():
        return get_oqs_resource("/CA.crt")

    test_cfg = [
        TestConfig("pq.cloudflareresearch.com", "x25519/Kyber-768-r3"),
        TestConfig("pq.cloudflareresearch.com", "x25519/ML-KEM-768"),
        TestConfig("google.com", "x25519/Kyber-768-r3"),
        TestConfig("google.com", "x25519/ML-KEM-768"),

        TestConfig("qsc.eu-de.kms.cloud.ibm.com", "secp256r1/Kyber-512-r3"),
        TestConfig("qsc.eu-de.kms.cloud.ibm.com", "secp384r1/Kyber-768-r3"),
        TestConfig("qsc.eu-de.kms.cloud.ibm.com", "secp521r1/Kyber-1024-r3"),
        TestConfig("qsc.eu-de.kms.cloud.ibm.com", "Kyber-512-r3"),
        TestConfig("qsc.eu-de.kms.cloud.ibm.com", "Kyber-768-r3"),
        TestConfig("qsc.eu-de.kms.cloud.ibm.com", "Kyber-1024-r3"),
    ]

    oqsp = get_oqs_ports()
    oqs_test_ca = get_oqs_rootca()
    if oqsp and oqs_test_ca:
        # src/scripts/test_cli.py --run-online-tests ./botan pqc_hybrid_tests
        test_cfg += [
            TestConfig("test.openquantumsafe.org", "x25519/ML-KEM-768", port=oqsp['X25519MLKEM768'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp256r1/ML-KEM-768", port=oqsp['SecP256r1MLKEM768'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "x25519/Kyber-512-r3", port=oqsp['x25519_kyber512'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "x25519/Kyber-768-r3", port=oqsp['x25519_kyber768'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "x448/Kyber-768-r3", port=oqsp['x448_kyber768'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp256r1/Kyber-512-r3", port=oqsp['p256_kyber512'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp256r1/Kyber-768-r3", port=oqsp['p256_kyber768'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp384r1/Kyber-768-r3", port=oqsp['p384_kyber768'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp521r1/Kyber-1024-r3", port=oqsp['p521_kyber1024'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "Kyber-512-r3", port=oqsp['kyber512'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "Kyber-768-r3", port=oqsp['kyber768'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "Kyber-1024-r3", port=oqsp['kyber1024'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "eFrodoKEM-640-SHAKE", port=oqsp['frodo640shake'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "eFrodoKEM-976-SHAKE", port=oqsp['frodo976shake'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "eFrodoKEM-1344-SHAKE", port=oqsp['frodo1344shake'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "eFrodoKEM-640-AES", port=oqsp['frodo640aes'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "eFrodoKEM-976-AES", port=oqsp['frodo976aes'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "eFrodoKEM-1344-AES", port=oqsp['frodo1344aes'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "x25519/eFrodoKEM-640-SHAKE", port=oqsp['x25519_frodo640shake'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "x25519/eFrodoKEM-640-AES", port=oqsp['x25519_frodo640aes'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "x448/eFrodoKEM-976-SHAKE", port=oqsp['x448_frodo976shake'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "x448/eFrodoKEM-976-AES", port=oqsp['x448_frodo976aes'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp256r1/eFrodoKEM-640-SHAKE", port=oqsp['p256_frodo640shake'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp256r1/eFrodoKEM-640-AES", port=oqsp['p256_frodo640aes'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp384r1/eFrodoKEM-976-SHAKE", port=oqsp['p384_frodo976shake'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp384r1/eFrodoKEM-976-AES", port=oqsp['p384_frodo976aes'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp521r1/eFrodoKEM-1344-SHAKE", port=oqsp['p521_frodo1344shake'], ca=oqs_test_ca),
            TestConfig("test.openquantumsafe.org", "secp521r1/eFrodoKEM-1344-AES", port=oqsp['p521_frodo1344aes'], ca=oqs_test_ca),
        ]
    else:
        logging.info("failed to pull OQS port assignment, skipping OQS...")

    for cfg in test_cfg:
        cfg.setup(tmp_dir)
        stdout = cfg.run()
        if "Handshake complete" not in stdout:
            logging.error('Failed to complete handshake (%s with %s): %s', cfg.host, cfg.kex_algo, stdout)


def cli_tls_http_server_tests(tmp_dir):
    if not run_socket_tests() or not check_for_command("tls_http_server"):
        return

    server_port = port_for('tls_http_server')

    class BotanHttpServer(AsyncTestProcess):
        def __init__(self, tmp_dir, port, clients=0):
            super().__init__("HTTP Server")
            self.port = port
            self.clients = clients
            self.cert_suite = ServerCertificateSuite(tmp_dir, "secp384r1", "SHA-384")

        @property
        def ca_cert(self):
            return self.cert_suite.ca_cert

        async def __aenter__(self):
            server_cmd = [CLI_PATH, 'tls_http_server', f'--port={self.port}', f'--max-clients={self.clients}',
                          self.cert_suite.cert, self.cert_suite.private_key]

            await self._launch(server_cmd, b'Listening for new connections')

            return self

        async def __aexit__(self, *_):
            await self._finalize()

    async def run_async_test():
        async with BotanHttpServer(tmp_dir, server_port, 4) as tls_server:
            for tls_version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
                context = ssl.create_default_context(cafile=tls_server.ca_cert)
                context.minimum_version = tls_version
                context.maximum_version = tls_version

                conn = HTTPSConnection('localhost', port=server_port, context=context)
                conn.request("GET", "/", headers={"Connection": "close"})
                resp = conn.getresponse()

                if resp.status != 200:
                    logging.error('Unexpected response status %d', resp.status)

                body = str(resp.read())

                if body.find('TLS negotiation with Botan 3.') < 0:
                    logging.error('Unexpected response body %s', body)

                conn.request("POST", "/logout", headers={"Connection": "close"})
                resp = conn.getresponse()

                if resp.status != 405:
                    logging.error('Unexpected response status %d', resp.status)

    asyncio.run(run_async_test())

def cli_tls_proxy_tests(tmp_dir):
    # This was disabled in GH #3845 due to flakyness, then thought possibly
    # fixed and enabled again in Gh #4178. However the test still occasionally
    # fails. Disable it again pending diagnosis...
    if not run_socket_tests() or platform.system() == 'Windows' or not check_for_command("tls_proxy"):
        return

    server_port = port_for('tls_proxy_backend')
    proxy_port = port_for('tls_proxy')
    max_clients = 4

    server_response = binascii.hexlify(os.urandom(32))

    class Proxy(AsyncTestProcess):
        def __init__(self, tmp_dir, server_port, proxy_port, clients=0):
            super().__init__("Proxy")
            self.server_port = server_port
            self.proxy_port = proxy_port
            self.clients = clients

            self.cert_suite = ServerCertificateSuite(tmp_dir, "secp384r1", "SHA-384")

        @property
        def ca_cert(self):
            return self.cert_suite.ca_cert

        async def __aenter__(self):
            proxy_cmd = [CLI_PATH, 'tls_proxy', str(proxy_port), '127.0.0.1', str(server_port),
                         self.cert_suite.cert, self.cert_suite.private_key, f'--max-clients={self.clients}']

            await self._launch(proxy_cmd, b'Listening for new connections')

            return self

        async def __aexit__(self, *_):
            await self._finalize()

    def run_http_server():
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _fmt, *_args): # pylint: disable=arguments-differ
                pass  # muzzle log output

            def do_GET(self): # pylint: disable=invalid-name
                self.send_response(200)
                self.end_headers()
                self.wfile.write(server_response)

        httpd = HTTPServer(('', server_port), Handler)
        httpd.serve_forever()

    http_thread = threading.Thread(target=run_http_server)
    http_thread.daemon = True
    http_thread.start()

    async def run_async_test():
        async with Proxy(tmp_dir, server_port, proxy_port, max_clients) as tls_proxy:
            context = ssl.create_default_context(cafile=tls_proxy.ca_cert)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3

            for i in range(max_clients):
                # Make sure that TLS protocol version downgrade works
                if i > max_clients / 2:
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2

                conn = HTTPSConnection('localhost', port=proxy_port, context=context, timeout=20)
                conn.request("GET", "/")
                resp = conn.getresponse()

                if resp.status != 200:
                    logging.error('Unexpected response status %d', resp.status)

                body = resp.read()

                if body != server_response:
                    logging.error('Unexpected response from server %s', body)

    asyncio.run(run_async_test())

def cli_trust_root_tests(tmp_dir):
    pem_file = os.path.join(tmp_dir, 'pems')
    dn_file = os.path.join(tmp_dir, 'dns')

    test_cli("trust_roots", ['--dn-only', '--output=%s' % (dn_file)], "")

    dn_re = re.compile('(.+=\".+\")(,.+=\".+\")?')

    for line in open(dn_file, encoding='utf8'):
        if dn_re.match(line) is None:
            logging.error("Unexpected DN line %s", line)

    test_cli("trust_roots", ['--output=%s' % (pem_file)], "")

def cli_tss_tests(tmp_dir):
    data_file = os.path.join(tmp_dir, 'data')

    exp_hash = "53B3C59276AE30EA7FD882268E80FD96AD80CC9FEB15F9FB940E7C4B5CF80B9E"

    test_cli("rng", ["32", "--output=%s" % (data_file)], "")
    test_cli("hash", ["--no-fsname", data_file], exp_hash)

    m = 3
    n = 5

    test_cli("tss_split", [str(m), str(n), data_file, "--share-prefix=%s/split" % (tmp_dir)], "")

    share_files = []

    for i in range(1, n+1):
        share = os.path.join(tmp_dir, "split%d.tss" % (i))
        if not os.access(share, os.R_OK):
            logging.error("Failed to create expected split file %s", share)
        share_files.append(share)

    rec5 = os.path.join(tmp_dir, "recovered_5")
    test_cli("tss_recover", share_files + ["--output=%s" % (rec5)], "")
    test_cli("hash", ["--no-fsname", rec5], exp_hash)

    rec4 = os.path.join(tmp_dir, "recovered_4")
    test_cli("tss_recover", share_files[1:] + ["--output=%s" % (rec4)], "")
    test_cli("hash", ["--no-fsname", rec4], exp_hash)

    rec3 = os.path.join(tmp_dir, "recovered_3")
    test_cli("tss_recover", share_files[2:] + ["--output=%s" % (rec3)], "")
    test_cli("hash", ["--no-fsname", rec3], exp_hash)

    rec2 = os.path.join(tmp_dir, "recovered_2")
    test_cli("tss_recover", share_files[3:] + ["--output=%s" % (rec2)], "", None,
             "Error: Insufficient shares to do TSS reconstruction")


def cli_pk_encrypt_tests(tmp_dir):
    input_file = os.path.join(tmp_dir, 'input')
    ctext_file = os.path.join(tmp_dir, 'ctext')
    recovered_file = os.path.join(tmp_dir, 'recovered')
    rsa_priv_key = os.path.join(tmp_dir, 'rsa.priv')
    rsa_pub_key = os.path.join(tmp_dir, 'rsa.pub')

    test_cli("keygen", ["--algo=RSA", "--params=2048", "--output=%s" % (rsa_priv_key)], "")

    key_hash = "D1621B7D1272545F8CCC220BC7F6F5BAF0150303B19299F0C5B79C095B3CDFC0"
    test_cli("hash", ["--no-fsname", "--algo=SHA-256", rsa_priv_key], key_hash)

    test_cli("pkcs8", ["--pub-out", "%s/rsa.priv" % (tmp_dir), "--output=%s" % (rsa_pub_key)], "")

    # Generate a random input file
    test_cli("rng", ["10", "16", "32", "--output=%s" % (input_file)], "")

    # Because we used a fixed DRBG for each invocation the same ctext is generated each time
    rng_output_hash = "32F5E7B61357DE8397EFDA1E598379DFD5EE21767BDF4E2A435F05117B836AC6"
    ctext_hash = "FD39EDCAEA56B0FD39AC5CF700EDA79CD80A938C964E78E56BAA6AF742D476A2"

    test_cli("hash", ["--no-fsname", "--algo=SHA-256", input_file], rng_output_hash)

    # Encrypt and verify ciphertext is the expected value
    test_cli("pk_encrypt", [rsa_pub_key, input_file, "--output=%s" % (ctext_file)], "")
    test_cli("hash", ["--no-fsname", "--algo=SHA-256", ctext_file], ctext_hash)

    # Decrypt and verify plaintext is recovered
    test_cli("pk_decrypt", [rsa_priv_key, ctext_file, "--output=%s" % (recovered_file)], "")
    test_cli("hash", ["--no-fsname", "--algo=SHA-256", recovered_file], rng_output_hash)

def cli_uuid_tests(_tmp_dir):
    test_cli("uuid", [], "D80F88F6-ADBE-45AC-B10C-3602E67D985B")

    uuid_re = re.compile(r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}')

    output = test_cli("uuid", [])

    if uuid_re.match(output) is None:
        logging.error('Bad uuid output %s', output)

def cli_tls_client_hello_tests(_tmp_dir):

    chellos = [
        # TLS 1.2
        ("6073536D3FA201A37C1F3944F6DCDD5A83FAA67DF4B1C9CBE4FA4399FDE7673C", "16030100cf010000cb03035b3cf2457b864d7bef2a4b1f84fc3ced2b68d9551f3455ffdd305af277a91bb200003a16b816b716ba16b9cca9cca8c02cc030c02bc02fc0adc0acc024c00ac028c014c023c009c027c013ccaa009f009ec09fc09e006b003900670033010000680000000e000c000009676d61696c2e636f6d000500050100000000000a001a0018001d0017001a0018001b0019001c01000101010201030104000b00020100000d00140012080508040806050106010401050306030403001600000017000000230000ff01000100"),

        # TLS 1.3
        ("4D8BB87026C6AEB1356234A01BD62C7DEFB3FEA298B8C50900F5D3F3ADDAADEB", "1603010106010001020303657033B5C89B0356097C9D43B3917BC0D743E34CB118E1DD3FC806EC9CED2FB120657033B589AD50CADDC8CBA0B805A9841DB3A4F92334C1A44EE968DD4B2983450018130313021301CCA9CCA8C02CC030C02BC02FCCAA009F009E010000A10000000E000C0000096C6F63616C686F7374000A001A0018001D0017001A0018001B0019001C01000101010201030104003300260024001D002002CBD31A5D5754EFD5C8F5152E27302681278A710A22B04403EF9EF0F5F95C1E002B00050403040303000D00140012080508040806050106010401050306030403002D00020101000500050100000000FF01000100002300000017000000160000000B00020100"),
    ]

    for output_hash, chello in chellos:
        output = test_cli("tls_client_hello", ["--hex", "-"], None, chello)
        test_cli("hash", ["--no-fsname", "--algo=SHA-256", "-"], output_hash, output)

def cli_speed_pk_tests(_tmp_dir):
    msec = 1

    pk_algos = ["ECDSA", "ECDH", "SM2", "ECKCDSA", "ECGDSA", "GOST-34.10",
                "DH", "DSA", "ElGamal", "Ed25519", "Ed448", "X25519", "X448",
                "RSA", "RSA_keygen", "XMSS", "Kyber", "Dilithium", "SLH-DSA"]

    output = test_cli("speed", ["--msec=%d" % (msec)] + pk_algos, None).split('\n')

    # ECDSA-secp256r1 106 keygen/sec; 9.35 ms/op 37489733 cycles/op (1 op in 9 ms)
    format_re = re.compile(r'^.* [0-9]+ ([A-Za-z0-9 ]+)/sec; [0-9]+\.[0-9]+ ms/op .*\([0-9]+ (op|ops) in [0-9\.]+ ms\)')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

def cli_speed_pbkdf_tests(_tmp_dir):
    msec = 1
    pbkdf_ops = ['bcrypt', 'passhash9', 'argon2']

    format_re = re.compile(r'^.* [0-9]+ /sec; [0-9]+\.[0-9]+ ms/op .*\([0-9]+ (op|ops) in [0-9]+(\.[0-9]+)? ms\)')
    for op in pbkdf_ops:
        output = test_cli("speed", ["--msec=%d" % (msec), op], None).split('\n')
        for line in output:
            if format_re.match(line) is None:
                logging.error("Unexpected line %s", line)

def cli_speed_table_tests(_tmp_dir):
    msec = 1

    version_re = re.compile(r'^Botan 3\.[0-9]+\.[0-9](\-.*[0-9]+)? \(.*, revision .*, distribution .*\)')
    cpuid_re = re.compile(r'^CPUID: [a-z_0-9 ]*$')
    format_re = re.compile(r'^.* buffer size [0-9]+ bytes: [0-9]+\.[0-9]+ MiB\/sec .*\([0-9]+\.[0-9]+ MiB in [0-9]+\.[0-9]+ ms\)')
    tbl_hdr_re = re.compile(r'^algo +operation +1024 bytes$')
    tbl_val_re = re.compile(r'^.* +(encrypt|decrypt) +[0-9]+(\.[0-9]{2})$')

    output = test_cli("speed", ["--format=table", "--msec=%d" % (msec), "AES-128"], None).split('\n')

    if len(output) != 11:
        logging.error('Unexpected number of lines from table output')

    if version_re.match(output[0]) is None:
        logging.error("Unexpected version line %s", output[0])

    if output[1] != '':
        if cpuid_re.match(output[1]) is None:
            logging.error("Unexpected cpuid line %s", output[1])
    elif output[2] != '':
        logging.error("Expected newline got %s", output[2])

    if format_re.match(output[3]) is None:
        logging.error("Unexpected line %s", output[3])
    if format_re.match(output[4]) is None:
        logging.error("Unexpected line %s", output[4])
    if output[5] != '':
        logging.error("Expected newline got %s", output[5])

    if tbl_hdr_re.match(output[6]) is None:
        logging.error("Unexpected table header %s", output[6])
    if tbl_val_re.match(output[7]) is None:
        logging.error("Unexpected table header %s", output[7])
    if tbl_val_re.match(output[8]) is None:
        logging.error("Unexpected table header %s", output[8])
    if output[9] != '':
        logging.error("Expected newline got %s", output[9])
    if output[10].find('results are the number of 1000s bytes processed per second') < 0:
        logging.error("Unexpected trailing message got %s", output[10])

def cli_speed_invalid_option_tests(_tmp_dir):
    speed_usage = "Usage: speed --msec=500 --format=default --ecc-groups= --buf-size=1024 --clear-cpuid= --cpu-clock-speed=0 --cpu-clock-ratio=1.0 *algos"

    test_cli("speed", ["--buf-size=0", "--msec=1", "AES-128"],
             expected_stderr="Usage error: Cannot have a zero-sized buffer\n%s" % (speed_usage))

    test_cli("speed", ["--buf-size=F00F", "--msec=1", "AES-128"],
             expected_stderr="Usage error: Invalid integer value 'F00F' for option buf-size\n%s" % (speed_usage))

    test_cli("speed", ["--buf-size=90000000", "--msec=1", "AES-128"],
             expected_stderr="Usage error: Specified buffer size is too large\n%s" % (speed_usage))

    test_cli("speed", ["--clear-cpuid=goku", "--msec=1", "AES-128"],
             expected_stderr="Warning don't know CPUID flag 'goku'")

def cli_speed_math_tests(_tmp_dir):
    msec = 1
    # these all have a common output format
    math_ops = ['mp_mul', 'mp_div', 'mp_div10', 'modexp', 'random_prime', 'inverse_mod',
                'rfc3394', 'fpe_fe1', 'ecdsa_recovery', 'ecc',
                'bn_redc', 'nistp_redc', 'primality_test']

    format_re = re.compile(r'^.* [0-9]+ /sec; [0-9]+\.[0-9]+ ms/op .*\([0-9]+ (op|ops) in [0-9]+(\.[0-9]+)? ms\)')
    for op in math_ops:
        output = test_cli("speed", ["--msec=%d" % (msec), op], None).split('\n')
        for line in output:
            if format_re.match(line) is None:
                logging.error("Unexpected line %s", line)

def cli_speed_tests(_tmp_dir):

    msec = 1

    output = test_cli("speed", ["--msec=%d" % (msec), "--buf-size=64,512", "AES-128"], None).split('\n')

    if len(output) % 4 != 0:
        logging.error("Unexpected number of lines for AES-128 speed test")

    format_re = re.compile(r'^.* .* buffer size [0-9]+ bytes: [0-9]+\.[0-9]+ MiB\/sec .*\([0-9]+\.[0-9]+ MiB in [0-9]+\.[0-9]+ ms\)')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

    output = test_cli("speed", ["--msec=%d" % (msec), "ChaCha20", "SHA-256", "HMAC(SHA-256)"], None).split('\n')

    format_re = re.compile(r'^.* buffer size [0-9]+ bytes: [0-9]+\.[0-9]+ MiB\/sec .*\([0-9]+\.[0-9]+ MiB in [0-9]+\.[0-9]+ ms\)')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

    output = test_cli("speed", ["--msec=%d" % (msec), "AES-128/GCM"], None).split('\n')
    format_re_ks = re.compile(r'^AES-128/GCM\(16\).* [0-9]+ key schedule/sec; [0-9]+\.[0-9]+ ms/op .*\([0-9]+ (op|ops) in [0-9\.]+ ms\)')
    format_re_cipher = re.compile(r'^AES-128/GCM\(16\) .* buffer size [0-9]+ bytes: [0-9]+\.[0-9]+ MiB\/sec .*\([0-9]+\.[0-9]+ MiB in [0-9]+\.[0-9]+ ms\)')
    for line in output:
        if format_re_ks.match(line) is None:
            if format_re_cipher.match(line) is None:
                logging.error('Unexpected line %s', line)

    output = test_cli("speed", ["--msec=%d" % (msec), "scrypt"], None).split('\n')

    format_re = re.compile(r'^scrypt-[0-9]+-[0-9]+-[0-9]+ \([0-9]+ MiB\) [0-9]+ /sec; [0-9]+\.[0-9]+ ms/op .*\([0-9]+ (op|ops) in [0-9\.]+ ms\)')

    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

    output = test_cli("speed", ["--msec=%d" % (msec), "RNG"], None).split('\n')

    # ChaCha_RNG generate buffer size 1024 bytes: 954.431 MiB/sec 4.01 cycles/byte (477.22 MiB in 500.00 ms)
    format_re = re.compile(r'^.* generate buffer size [0-9]+ bytes: [0-9]+\.[0-9]+ MiB/sec .*\([0-9]+\.[0-9]+ MiB in [0-9]+\.[0-9]+ ms')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

    # Entropy source rdseed output 128 bytes estimated entropy 0 in 0.02168 ms total samples 32
    output = test_cli("speed", ["--msec=%d" % (msec), "entropy"], None).split('\n')
    format_re = re.compile(r'^Entropy source [_a-z0-9]+ output [0-9]+ bytes estimated entropy [0-9]+ in [0-9]+\.[0-9]+ ms .*total samples [0-9]+')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

    output = test_cli("speed", ["--msec=%d" % (msec), "zfec"], None).split('\n')
    format_re = re.compile(r'^zfec [0-9]+/[0-9]+ (encode|decode) buffer size [0-9]+ bytes: [0-9]+\.[0-9]+ MiB/sec .*\([0-9]+\.[0-9]+ MiB in [0-9]+\.[0-9]+ ms')
    for line in output:
        if format_re.match(line) is None:
            logging.error("Unexpected line %s", line)

    output = test_cli("speed", ["--msec=%d" % (msec), "--format=json", "AES-128"], None)

    json_blob = json.loads(output)
    if len(json_blob) < 2:
        logging.error("Unexpected size for JSON output")

    for b in json_blob:
        for field in ['algo', 'op', 'events', 'bps', 'buf_size', 'nanos']:
            if field not in b:
                logging.error('Missing field %s in JSON record %s', field, b)

def run_test(fn_name, fn):
    start = time.time()
    tmp_dir = tempfile.mkdtemp(prefix='botan_cli_')
    try:
        fn(tmp_dir)
    except Exception as e:
        logging.info(traceback.format_exc())
        logging.error("Test %s threw exception: %s", fn_name, e)

    shutil.rmtree(tmp_dir)
    end = time.time()
    logging.info("Ran %s in %.02f sec", fn_name, end-start)

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser(
        formatter=optparse.IndentedHelpFormatter(max_help_position=50))

    parser.add_option('--verbose', action='store_true', default=False)
    parser.add_option('--quiet', action='store_true', default=False)
    parser.add_option('--threads', action='store', type='int', default=0)
    parser.add_option('--run-slow-tests', action='store_true', default=False)
    parser.add_option('--run-online-tests', action='store_true', default=False)
    parser.add_option('--test-data-dir', default='.')

    (options, args) = parser.parse_args(args)

    setup_logging(options)

    if len(args) < 2:
        logging.error("Usage: %s path_to_botan_cli [test_regex]", args[0])
        return 1

    if not os.access(args[1], os.X_OK):
        logging.error("Could not access/execute %s", args[1])
        return 2

    threads = options.threads
    if threads == 0:
        threads = multiprocessing.cpu_count()

    global CLI_PATH
    CLI_PATH = args[1]

    global TEST_DATA_DIR
    TEST_DATA_DIR = os.path.join(options.test_data_dir, 'src/tests/data/timing/')

    test_regex = None
    if len(args) == 3:
        try:
            test_regex = re.compile(args[2])
        except re.error as e:
            logging.error("Invalid regex: %s", str(e))
            return 1

    slow_test_fns = [
        cli_speed_tests,
        cli_speed_pk_tests,
        cli_speed_math_tests,
        cli_speed_pbkdf_tests,
        cli_speed_table_tests,
        cli_speed_invalid_option_tests,
        cli_xmss_sign_tests,
    ]

    fast_test_fns = [
        cli_argon2_tests,
        cli_asn1_tests,
        cli_base32_tests,
        cli_base58_tests,
        cli_base64_tests,
        cli_bcrypt_tests,
        cli_cc_enc_tests,
        cli_cycle_counter,
        cli_cert_issuance_tests,
        cli_cert_issuance_alternative_algos_tests,
        cli_compress_tests,
        cli_config_tests,
        cli_cpuid_tests,
        cli_dl_group_info_tests,
        cli_ec_group_info_tests,
        cli_entropy_tests,
        cli_factor_tests,
        cli_gen_dl_group_tests,
        cli_gen_prime_tests,
        cli_hash_tests,
        cli_help_tests,
        cli_hex_tests,
        cli_hmac_tests,
        cli_is_prime_tests,
        cli_key_tests,
        cli_marvin_tests,
        cli_mod_inverse_tests,
        cli_pbkdf_tune_tests,
        cli_pk_encrypt_tests,
        cli_pk_workfactor_tests,
        cli_psk_db_tests,
        cli_rng_tests,
        cli_roughtime_check_tests,
        cli_roughtime_tests,
        cli_timing_test_tests,
        cli_tls_ciphersuite_tests,
        cli_tls_client_hello_tests,
        cli_tls_http_server_tests,
        cli_tls_proxy_tests,
        cli_tls_socket_tests,
        cli_tls_online_pqc_hybrid_tests,
        cli_trust_root_tests,
        cli_tss_tests,
        cli_uuid_tests,
        cli_version_tests,
        cli_zfec_tests,
        ]

    test_fns = []

    if options.run_slow_tests:
        test_fns = slow_test_fns + fast_test_fns
    else:
        test_fns = fast_test_fns

    global ONLINE_TESTS
    ONLINE_TESTS = options.run_online_tests

    tests_to_run = []
    for fn in test_fns:
        fn_name = fn.__name__

        if test_regex is None or test_regex.search(fn_name) is not None:
            tests_to_run.append((fn_name, fn))

    start_time = time.time()

    if threads > 1:
        with ThreadPool(processes=threads) as pool:
            results = []
            for test in tests_to_run:
                results.append(pool.apply_async(run_test, test))

            for result in results:
                result.get()
    else:
        for test in tests_to_run:
            run_test(test[0], test[1])

    end_time = time.time()

    print("Ran %d tests with %d failures in %.02f seconds" % (
        TESTS_RUN, TESTS_FAILED, end_time - start_time))

    if TESTS_FAILED > 0:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
