#!/usr/bin/env python2

"""
Used to generate src/tls/tls_suite_info.cpp

(C) 2011, 2012, 2013 Jack Lloyd

Distributed under the terms of the Botan license

"""

import sys
import re
import datetime
import hashlib

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

    if mac_algo == '8' and cipher[-1] == 'CCM':
        cipher = cipher[:-1]
        mac_algo = 'CCM_8'

    if mac_algo == 'CCM':
        cipher += ['CCM']
        mac_algo = 'SHA256'
    elif mac_algo == 'CCM_8':
        cipher += ['CCM-8']
        mac_algo = 'SHA256'

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
        'PSK_DHE': 'DHE_PSK',
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
        if mode not in ['CBC', 'GCM', 'CCM-8', 'CCM', 'OCB']:
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

def open_input(args):
    iana_url = 'https://www.iana.org/assignments/tls-parameters/tls-parameters.txt'

    if len(args) == 1:
        try:
            return open('tls-parameters.txt')
        except:
            pass

        import urllib2
        return urllib2.urlopen(iana_url)
    else:
         return open(args[1])

def main(args = None):
    if args is None:
        args = sys.argv

    weak_crypto = ['EXPORT', 'RC2', 'IDEA', '_DES_', 'WITH_NULL']
    static_dh = ['ECDH_ECDSA', 'ECDH_RSA', 'DH_DSS', 'DH_RSA'] # not supported
    protocol_goop = ['SCSV', 'KRB5']
    maybe_someday = ['ARIA', 'RSA_PSK']
    not_supported = weak_crypto + static_dh + protocol_goop + maybe_someday

    include_srp_aead = False
    include_ocb = False
    include_eax = False
    save_file = True

    ciphersuite_re = re.compile(' +0x([0-9a-fA-F][0-9a-fA-F]),0x([0-9a-fA-F][0-9a-fA-F]) + TLS_([A-Za-z_0-9]+) ')

    suites = {}
    suite_codes = {}

    contents = ''

    for line in open_input(args):
        contents += line
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

    sha1 = hashlib.sha1()
    sha1.update(contents)
    contents_hash = sha1.hexdigest()

    if save_file:
        out = open('tls-parameters.txt', 'w')
        out.write(contents)
        out.close()

    def define_custom_ciphersuite(name, code):
        suites[name] = (code, to_ciphersuite_info(code, name))

    # From http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
    define_custom_ciphersuite('DHE_DSS_WITH_RC4_128_SHA', '0066')

    # Expermental things
    if include_ocb:
        define_custom_ciphersuite('ECDHE_ECDSA_AES_128_OCB_SHA256', 'FF80')
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_256_OCB_SHA384', 'FF81')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_128_OCB_SHA256', 'FF82')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_256_OCB_SHA384', 'FF83')

        define_custom_ciphersuite('ECDHE_PSK_WITH_AES_128_OCB_SHA256', 'FF85')
        define_custom_ciphersuite('ECDHE_PSK_WITH_AES_256_OCB_SHA384', 'FF86')

    if include_eax:
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_128_EAX_SHA256', 'FF90')
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_256_EAX_SHA384', 'FF91')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_128_EAX_SHA256', 'FF92')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_256_EAX_SHA384', 'FF93')

    if include_srp_aead:
        define_custom_ciphersuite('SRP_SHA_WITH_AES_256_GCM_SHA384', 'FFA0')
        define_custom_ciphersuite('SRP_SHA_RSA_WITH_AES_256_GCM_SHA384', 'FFA1')
        define_custom_ciphersuite('SRP_SHA_DSS_WITH_AES_256_GCM_SHA384', 'FFA2')
        define_custom_ciphersuite('SRP_SHA_ECDSA_WITH_AES_256_GCM_SHA384', 'FFA3')

        if include_ocb:
            define_custom_ciphersuite('SRP_SHA_WITH_AES_256_OCB_SHA384', 'FFA4')
            define_custom_ciphersuite('SRP_SHA_RSA_WITH_AES_256_OCB_SHA384', 'FFA5')
            define_custom_ciphersuite('SRP_SHA_DSS_WITH_AES_256_OCB_SHA384', 'FFA6')
            define_custom_ciphersuite('SRP_SHA_ECDSA_WITH_AES_256_OCB_SHA384', 'FFA7')

        if include_eax:
            define_custom_ciphersuite('SRP_SHA_WITH_AES_256_EAX_SHA384', 'FFA8')
            define_custom_ciphersuite('SRP_SHA_RSA_WITH_AES_256_EAX_SHA384', 'FFA9')
            define_custom_ciphersuite('SRP_SHA_DSS_WITH_AES_256_EAX_SHA384', 'FFAA')
            define_custom_ciphersuite('SRP_SHA_ECDSA_WITH_AES_256_EAX_SHA384', 'FFAB')


    def header():
        return """/*
* TLS cipher suite information
*
* This file was automatically generated from the IANA assignments
* (tls-parameters.txt hash %s)
* by %s on %s
*
* Released under the terms of the Botan license
*/
""" % (contents_hash, sys.argv[0], datetime.date.today().strftime("%Y-%m-%d"))

    print header()

    print """#include <botan/tls_ciphersuite.h>

namespace Botan {

namespace TLS {

Ciphersuite Ciphersuite::by_id(u16bit suite)
   {
   switch(suite)
      {"""

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
