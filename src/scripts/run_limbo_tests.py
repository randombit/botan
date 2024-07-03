#!/usr/bin/env python3

"""
Runs the tests from https://github.com/C2SP/x509-limbo
"""

from botan3 import X509Cert
from dateutil import parser
import json
import datetime
import optparse # pylint: disable=deprecated-module
import re
import subprocess
import sys

ignored_tests = {}

tests_that_succeed_unexpectedly = {
    'rfc5280::aki::critical-aki unexpected': 'Conflates CA and verifier requirements',
    'rfc5280::aki::critical-aki': 'Conflates CA and verifier requirements',
    'rfc5280::aki::intermediate-missing-aki': 'Conflates CA and verifier requirements',
    'rfc5280::aki::leaf-missing-aki': 'Conflates CA and verifier requirements',
    'rfc5280::ee-critical-aia-invalid': 'Conflates CA and verifier requirements',
    'rfc5280::nc::permitted-dns-match-noncritical': 'Conflates CA and verifier requirements',
    'rfc5280::pc::ica-noncritical-pc': 'Conflates CA and verifier requirements',
    'rfc5280::root-non-critical-basic-constraints': 'Conflates CA and verifier requirements',
    'rfc5280::san::noncritical-with-empty-subject': 'Conflates CA and verifier requirements',
    'rfc5280::serial::too-long': 'Conflates CA and verifier requirements',
    'rfc5280::serial::zero': 'Conflates CA and verifier requirements',
    'rfc5280::ski::intermediate-missing-ski': 'Conflates CA and verifier requirements',
    'rfc5280::ski::root-missing-ski': 'Conflates CA and verifier requirements',

    'webpki::aki::root-with-aki-missing-keyidentifier': 'Conflates CA and verifier requirements',
    'webpki::aki::root-with-aki-authoritycertissuer': 'Conflates CA and verifier requirements',
    'webpki::aki::root-with-aki-authoritycertserialnumber': 'Conflates CA and verifier requirements',
    'webpki::aki::root-with-aki-all-fields': 'Conflates CA and verifier requirements',
    'webpki::ee-basicconstraints-ca': 'Conflates CA and verifier requirements',
    'webpki::eku::ee-without-eku': 'Conflates CA and verifier requirements',
    'webpki::san::no-san': 'Conflates CA and verifier requirements',
    'webpki::san::san-critical-with-nonempty-subject': 'Conflates CA and verifier requirements',
    'webpki::v1-cert': 'Conflates CA and verifier requirements',
    'webpki::forbidden-rsa-not-divisable-by-8-in-root': 'Conflates CA and verifier requirements',
    'webpki::forbidden-rsa-key-not-divisable-by-8-in-leaf': 'Conflates CA and verifier requirements',
    'webpki::forbidden-dsa-leaf': 'Conflates CA and verifier requirements',
    'webpki::forbidden-dsa-root': 'Conflates CA and verifier requirements',

    'webpki::forbidden-p192-leaf': 'We do not place restrictions on the leaf key',
    'webpki::forbidden-weak-rsa-in-leaf': 'We do not place restrictions on the leaf key',

    'webpki::san::wildcard-embedded-leftmost-san': 'CABF rule not RFC 5280',
    'webpki::ca-as-leaf': 'Not applicable outside of webpki',

    'webpki::explicit-curve': 'Deprecated but not gone yet',
    'rfc5280::nc::invalid-dnsname-leading-period': 'Common extension',

    'rfc5280::nc::nc-forbids-othername': 'Othername is a NULL which we drop',
    'webpki::san::wildcard-embedded-ulabel-san': 'Needs investigation',
    'webpki::malformed-aia': 'Needs investigation',

    # A number of tests (736, 737, ...) seem to make the implicit assumption
    # that if a name constraint applies to a certificate then we should not
    # ever use the CN as the hostname, even if the ee cert does not have a SAN
    'bettertls::nameconstraints::tc736': 'See comment above',
    'bettertls::nameconstraints::tc737': 'Same as 736',
    'bettertls::nameconstraints::tc738': 'Same as 736',
    'bettertls::nameconstraints::tc742': 'Same as 736',
    'bettertls::nameconstraints::tc743': 'Same as 736',
    'bettertls::nameconstraints::tc744': 'Same as 736',
    'bettertls::nameconstraints::tc745': 'Same as 736',
    'bettertls::nameconstraints::tc746': 'Same as 736',
    'bettertls::nameconstraints::tc747': 'Same as 736',
    'bettertls::nameconstraints::tc751': 'Same as 736',
    'bettertls::nameconstraints::tc752': 'Same as 736',
    'bettertls::nameconstraints::tc753': 'Same as 736',
    'bettertls::nameconstraints::tc754': 'Same as 736',
    'bettertls::nameconstraints::tc755': 'Same as 736',
    'bettertls::nameconstraints::tc756': 'Same as 736',
    'bettertls::nameconstraints::tc760': 'Same as 736',
    'bettertls::nameconstraints::tc761': 'Same as 736',
    'bettertls::nameconstraints::tc762': 'Same as 736',
    'bettertls::nameconstraints::tc763': 'Same as 736',
    'bettertls::nameconstraints::tc764': 'Same as 736',
    'bettertls::nameconstraints::tc765': 'Same as 736',
    'bettertls::nameconstraints::tc769': 'Same as 736',
    'bettertls::nameconstraints::tc770': 'Same as 736',
    'bettertls::nameconstraints::tc771': 'Same as 736',
    'bettertls::nameconstraints::tc772': 'Same as 736',
    'bettertls::nameconstraints::tc773': 'Same as 736',
    'bettertls::nameconstraints::tc774': 'Same as 736',
    'bettertls::nameconstraints::tc778': 'Same as 736',
    'bettertls::nameconstraints::tc779': 'Same as 736',
    'bettertls::nameconstraints::tc780': 'Same as 736',
    'bettertls::nameconstraints::tc781': 'Same as 736',
    'bettertls::nameconstraints::tc782': 'Same as 736',
    'bettertls::nameconstraints::tc783': 'Same as 736',
    'bettertls::nameconstraints::tc787': 'Same as 736',
    'bettertls::nameconstraints::tc788': 'Same as 736',
    'bettertls::nameconstraints::tc789': 'Same as 736',
}

tests_that_fail_unexpectedly = {
    'rfc5280::nc::permitted-ipv6-match': 'IPv6 name constraints not implemented',

    'cve::cve-2024-0567': 'Possible path building bug',
    'rfc5280::root-and-intermediate-swapped': 'Possible path building bug',
    'rfc5280::nc::permitted-self-issued': 'Possible path building bug',
}

def report_success(test_id, modified_result, type):
    if modified_result:
        return "GOOD %s %s (MODIFIED RESULT)" % (test_id, type)
    else:
        return "GOOD %s %s as expected" % (test_id, type)

def report_failure(test_id, modified_result, type):
    if modified_result:
        return "FAIL %s unexpectedly %s (MODIFIED RESULT)" % (test_id, type)
    else:
        return "FAIL %s unexpectedly %s" % (test_id, type)

def dump_x509(who, cert):
    print("%s certificate\n" % (who))

    dump_cmd = ['openssl', 'x509', '-text', '-noout']
    proc = subprocess.run(dump_cmd,
                          input=bytes(cert, 'utf8'),
                          capture_output=True)

    print(proc.stdout.decode('utf8'))

def describe(test):
    print(test['description'])
    dump_x509('Peer', test['peer_certificate'])
    for inter in test['untrusted_intermediates']:
        dump_x509('Intermediate', inter)
    for root in test['trusted_certs']:
        dump_x509('Trusted', root)

def main(args = None):
    if args is None:
        args = sys.argv

    opts = optparse.OptionParser()

    opts.add_option('--run-only', metavar='REGEX', default=None,
                    help='Run only tests matching regex')
    opts.add_option('--stop-on-first-failure', action='store_true', default=False,
                    help='Exit immediately on first failure')

    opts.add_option('--verbose', default=False, action='store_true',
                    help='Print more details')

    (options, args) = opts.parse_args(args)

    if len(args) != 2:
        print("Expected usage: %s <limbo.json>" % (args[0]))
        return 1

    run_only = None
    if options.run_only is not None:
        run_only = re.compile(options.run_only)

    limbo_file = args[1]
    limbo_contents = open(limbo_file).read()
    limbo_json = json.loads(limbo_contents)

    if limbo_json['version'] != 1:
        print("Unexpected version in %s" % (limbo_file))
        return 1

    tests = 0
    success = 0
    ignored = 0
    unexpected_reject = 0
    unexpected_accept = 0
    modified = 0

    for test in limbo_json['testcases']:
        if run_only is not None:
            if run_only.match(test['id']) is None:
                continue

        if test['extended_key_usage'] != [] or test['max_chain_depth'] is not None:
            # we have no way of expressing this here
            ignored += 1
            if options.verbose:
                print("IGNR %s" % (test['id']))
            continue

        if test['id'] in ignored_tests:
            ignored += 1
            continue

        expected_to_pass = test['expected_result'] == 'SUCCESS'
        modified_result = False

        if test['id'] in tests_that_succeed_unexpectedly:
            assert(not expected_to_pass)
            expected_to_pass = True
            modified_result = True
            modified += 1
        elif test['id'] in tests_that_fail_unexpectedly:
            assert(expected_to_pass)
            expected_to_pass = False
            modified_result = True
            modified += 1

        tests += 1

        try:
            trust_roots = [X509Cert(buf=x) for x in test['trusted_certs']]
            intermediates = [X509Cert(buf=x) for x in test['untrusted_intermediates']]
            ee_cert = X509Cert(buf=test['peer_certificate'])
        except Exception as e:
            if not expected_to_pass:
                success += 1
            else:
                print("Test %s unexpected failed at parse time: got %s" % (test['id'], e))
                if options.verbose:
                    print(test)
            continue

        validation_time = 0
        if test['validation_time'] is not None:
            validation_time = int(parser.parse(test['validation_time']).timestamp())

        hostname = None
        if test['expected_peer_name'] != None:
            if test['expected_peer_name']['kind'] in ['DNS', 'IP']:
                hostname = test['expected_peer_name']['value']
            else:
                print("Ignoring peer_name kind %s" % (test['expected_peer_name']['kind']))

        result = ee_cert.verify(intermediates, trust_roots, required_strength=110,
                                hostname=hostname, reference_time=validation_time)

        if result == 0:
            if expected_to_pass:
                success += 1
                if options.verbose:
                    print(report_success(test['id'], modified_result, 'accepted'))
            else:
                unexpected_accept += 1
                print(report_failure(test['id'], modified_result, 'accepted'))
                if options.verbose:
                    describe(test)

                if options.stop_on_first_failure:
                    return 1
        else:
            if not expected_to_pass:
                success += 1
                if options.verbose:
                    print(report_success(test['id'], modified_result, 'rejected'))
            else:
                unexpected_reject += 1
                status_str = X509Cert.validation_status(result)
                print(report_failure(test['id'], modified_result, "rejected with '%s'" % (status_str)))
                if options.verbose:
                    describe(test)
                if options.stop_on_first_failure:
                    return 1

    print("Tests executed: %d" % (tests))
    print("Tests succeeding: %d" % (success))
    print("Tests ignored: %d" % (ignored))
    print("Tests with modified results: %d" % (modified))
    print("Test failures, unexpected accept: %d" % (unexpected_accept))
    print("Test failures, unexpected reject: %d" % (unexpected_reject))

    if unexpected_accept > 0 or unexpected_reject > 0:
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
