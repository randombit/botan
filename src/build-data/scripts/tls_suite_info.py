#!/usr/bin/env python2

"""
Used to generate src/tls/tls_suite_info.cpp

(C) 2011, 2012, 2013 Jack Lloyd

Distributed under the terms of the Botan license

First thing,
  wget https://www.iana.org/assignments/tls-parameters/tls-parameters.txt
"""

import sys
import re
import datetime

def to_ciphersuite_info(code, name):

    (sig_and_kex,cipher_and_mac) = name.split('_WITH_')

    if sig_and_kex == 'RSA':
        sig_algo = 'RSA'
        kex_algo = 'RSA'
    elif 'PSK' in sig_and_kex:
        sig_algo = ''
        kex_algo = sig_and_kex
    elif 'SRP' in sig_and_kex:
        srp_info = sig_and_kex.split('_')
        if len(srp_info) == 2: # 'SRP_' + hash
            kex_algo = sig_and_kex
            sig_algo = ''
        else:
            kex_algo = '_'.join(srp_info[0:-1])
            sig_algo = srp_info[-1]
    else:
        (kex_algo, sig_algo) = sig_and_kex.split('_')

    cipher_and_mac = cipher_and_mac.split('_')

    mac_algo = cipher_and_mac[-1]
    cipher = cipher_and_mac[:-1]

    cipher_info = {
        'RC4': ('RC4',None),
        'IDEA': ('IDEA',16),
        'DES': ('DES',8),
        '3DES': ('3DES',24),
        'CAMELLIA': ('Camellia',None),
        'AES': ('AES',None),
        'SEED': ('SEED',16),
        'ARIA': ('ARIA',16)
        }

    tls_to_botan_names = {
        'anon': '',
        'MD5': 'MD5',
        'SHA': 'SHA-1',
        'SHA256': 'SHA-256',
        'SHA384': 'SHA-384',
        'SHA512': 'SHA-512',
        'RC4': 'RC4',
        '3DES': 'TripleDES',
        'DSS': 'DSA',
        'ECDSA': 'ECDSA',
        'RSA': 'RSA',
        'SRP_SHA': 'SRP_SHA',
        'DHE': 'DH',
        'DH': 'DH',
        'ECDHE': 'ECDH',
        'ECDH': 'ECDH',
        '': '',
        'PSK': 'PSK',
        'DHE_PSK': 'DHE_PSK',
        'ECDHE_PSK': 'ECDHE_PSK',
        }

    mac_keylen = {
        'MD5': 16,
        'SHA-1': 20,
        'SHA-256': 32,
        'SHA-384': 48,
        'SHA-512': 64,
        }

    mac_algo = tls_to_botan_names[mac_algo]
    sig_algo = tls_to_botan_names[sig_algo]
    kex_algo = tls_to_botan_names[kex_algo]

    (cipher_algo, cipher_keylen) = cipher_info[cipher[0]]

    if cipher_keylen is None:
        cipher_keylen = int(cipher[1]) / 8

    if cipher_algo in ['AES', 'Camellia']:
        cipher_algo += '-%d' % (cipher_keylen*8)

    modestr = ''
    mode = ''
    ivlen = 0
    if cipher_algo != 'RC4':
        mode = cipher[-1]
        if mode not in ['CBC', 'GCM', 'CCM', 'OCB']:
            print "#warning Unknown mode %s" % (' '.join(cipher))

        ivlen = 8 if cipher_algo == '3DES' else 16

        if mode != 'CBC':
            cipher_algo += '/' + mode

    if cipher_algo != 'RC4' and mode != 'CBC':
        return 'Ciphersuite(0x%s, "%s", "%s", "%s", %d, %d, "AEAD", %d, "%s")' % (
            code, sig_algo, kex_algo, cipher_algo, cipher_keylen, 4, 0, mac_algo)
    else:
        return 'Ciphersuite(0x%s, "%s", "%s", "%s", %d, %d, "%s", %d)' % (
            code, sig_algo, kex_algo, cipher_algo, cipher_keylen, ivlen, mac_algo, mac_keylen[mac_algo])

def main(args = None):
    if args is None:
        args = sys.argv

    weak_crypto = ['EXPORT', 'RC2', '_DES_', 'WITH_NULL']
    weird_crypto = ['ARIA', 'IDEA']
    static_dh = ['ECDH_ECDSA', 'ECDH_RSA', 'DH_DSS', 'DH_RSA']
    protocol_goop = ['SCSV', 'KRB5']
    just_not_yet = ['RSA_PSK', 'CCM']

    not_supported = weak_crypto + weird_crypto + static_dh + protocol_goop + just_not_yet

    input = open('tls-parameters.txt')

    ciphersuite_re = re.compile(' +0x([0-9a-fA-F][0-9a-fA-F]),0x([0-9a-fA-F][0-9a-fA-F]) + TLS_([A-Za-z_0-9]+) ')

    suites = {}
    suite_codes = {}

    for line in input:
        match = ciphersuite_re.match(line)
        if match:
            code = match.group(1) + match.group(2)
            name = match.group(3)

            should_use = True
            for ns in not_supported:
                if ns in name:
                    should_use = False

            if should_use:
                suites[name] = (code, to_ciphersuite_info(code, name))

    # From http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
    suites['DHE_DSS_WITH_RC4_128_SHA'] = ('0066', to_ciphersuite_info('0066', 'DHE_DSS_WITH_RC4_128_SHA'))

    #suites['ECDHE_RSA_WITH_AES_128_OCB_SHA256'] = ('FF66', to_ciphersuite_info('FF66', 'ECDHE_RSA_WITH_AES_128_OCB_SHA256'))

    print """/*
* TLS cipher suite information
*
* This file was automatically generated from the IANA assignments
* by %s on %s
*
* Released under the terms of the Botan license
*/

#include <botan/tls_ciphersuite.h>

namespace Botan {

namespace TLS {

Ciphersuite Ciphersuite::by_id(u16bit suite)
   {
   switch(suite)
      {""" % (sys.argv[0], datetime.date.today().strftime("%Y-%m-%d"))

    for k in sorted(suites.keys()):
        print "      case 0x%s: // %s" % (suites[k][0], k)
        print "         return %s;" % (suites[k][1])
        print

    print """      }

   return Ciphersuite(); // some unknown ciphersuite
   }

}

}"""

if __name__ == '__main__':
    sys.exit(main())
