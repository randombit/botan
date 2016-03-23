#!/usr/bin/env python2

"""
Used to generate lib/tls/tls_suite_info.cpp from IANA params

(C) 2011, 2012, 2013, 2014, 2015 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import re
import datetime
import hashlib
import optparse

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
        cipher += ['CCM(8)']
        mac_algo = 'SHA256'

    cipher_info = {
        'CHACHA20': ('ChaCha',32),
        'IDEA': ('IDEA',16),
        'DES': ('DES',8),
        '3DES': ('3DES',24),
        'CAMELLIA': ('Camellia',None),
        'AES': ('AES',None),
        'SEED': ('SEED',16),
        'ARIA': ('ARIA',16),
        }

    tls_to_botan_names = {
        'anon': '',
        'MD5': 'MD5',
        'SHA': 'SHA-1',
        'SHA256': 'SHA-256',
        'SHA384': 'SHA-384',
        'SHA512': 'SHA-512',

        'CHACHA': 'ChaCha',
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

    if cipher[0] == 'CHACHA20' and cipher[1] == 'POLY1305':
        iv_len = 12
        if code in ['CC13', 'CC14', 'CC15']:
            iv_len = 0 # Google variant
        return 'Ciphersuite(0x%s, "%s", "%s", "%s", %d, %d, %d, "AEAD", %d, "%s")' % (
            code, sig_algo, kex_algo, "ChaCha20Poly1305", cipher_keylen, iv_len, 0, 0, mac_algo)

    mode = cipher[-1]
    if mode not in ['CBC', 'GCM', 'CCM(8)', 'CCM', 'OCB']:
        print "#warning Unknown mode %s" % (' '.join(cipher))

    ivlen = 8 if cipher_algo == '3DES' else 16

    if mode != 'CBC':
        if mode == 'OCB':
            cipher_algo += '/OCB(12)'
        else:
            cipher_algo += '/' + mode

    if mode == 'CBC':
        return 'Ciphersuite(0x%s, "%s", "%s", "%s", %d, %d, 0, "%s", %d)' % (
            code, sig_algo, kex_algo, cipher_algo, cipher_keylen, ivlen, mac_algo, mac_keylen[mac_algo])

    elif mode == 'OCB':
        return 'Ciphersuite(0x%s, "%s", "%s", "%s", %d, %d, %d, "AEAD", %d, "%s")' % (
            code, sig_algo, kex_algo, cipher_algo, cipher_keylen, 4, 0, 0, mac_algo)

    else:
        iv_bytes_from_hs = 4
        iv_bytes_from_rec = 8

        return 'Ciphersuite(0x%s, "%s", "%s", "%s", %d, %d, %d, "AEAD", %d, "%s")' % (
            code, sig_algo, kex_algo, cipher_algo, cipher_keylen, iv_bytes_from_hs, iv_bytes_from_rec, 0, mac_algo)

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

"""
Handle command line options
"""
def process_command_line(args):

    parser = optparse.OptionParser()

    parser.add_option('--with-ocb', action='store_true', default=True,
                      help='enable experimental OCB AEAD suites')
    parser.add_option('--without-ocb', action='store_false', dest='with_ocb',
                      help='disable experimental OCB AEAD suites')

    parser.add_option('--with-srp-aead', action='store_true', default=False,
                      help='add experimental SRP AEAD suites')
    parser.add_option('--with-eax', action='store_true', default=False,
                      help='add experimental EAX AEAD suites')

    parser.add_option('--save-download', action='store_true', default=True,
                      help='save downloaded tls-parameters.txt')

    parser.add_option('--output', '-o',
                      help='file to write output to (default %default)',
                      default='src/lib/tls/tls_suite_info.cpp')

    return parser.parse_args(args)

def main(args = None):
    if args is None:
        args = sys.argv

    weak_crypto = ['EXPORT', 'RC2', 'IDEA', 'RC4', '_DES_', 'WITH_NULL']
    static_dh = ['ECDH_ECDSA', 'ECDH_RSA', 'DH_DSS', 'DH_RSA'] # not supported
    protocol_goop = ['SCSV', 'KRB5']
    maybe_someday = ['ARIA', 'RSA_PSK']
    not_supported = weak_crypto + static_dh + protocol_goop + maybe_someday

    (options, args) = process_command_line(args)

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
                suites[code] = (name, to_ciphersuite_info(code, name))

    sha1 = hashlib.sha1()
    sha1.update(contents)
    contents_hash = sha1.hexdigest()

    if options.save_download:
        out = open('tls-parameters.txt', 'w')
        out.write(contents)
        out.close()

    def define_custom_ciphersuite(name, code):
        suites[code] = (name, to_ciphersuite_info(code, name))

    # Google servers - draft-agl-tls-chacha20poly1305-04
    define_custom_ciphersuite('ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'CC13')
    define_custom_ciphersuite('ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'CC14')
    define_custom_ciphersuite('DHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'CC15')

    # Expermental things
    if options.with_ocb:
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_128_OCB_SHA256', 'FFF0')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_256_OCB_SHA256', 'FFF1')
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_128_OCB_SHA256', 'FFF2')
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_256_OCB_SHA256', 'FFF3')
        define_custom_ciphersuite('DHE_RSA_WITH_AES_128_OCB_SHA256', 'FFF4')
        define_custom_ciphersuite('DHE_RSA_WITH_AES_256_OCB_SHA256', 'FFF5')

        define_custom_ciphersuite('PSK_WITH_AES_128_OCB_SHA256', 'FFF6')
        define_custom_ciphersuite('PSK_WITH_AES_256_OCB_SHA256', 'FFF7')
        define_custom_ciphersuite('ECDHE_PSK_WITH_AES_128_OCB_SHA256', 'FFF8')
        define_custom_ciphersuite('ECDHE_PSK_WITH_AES_256_OCB_SHA256', 'FFF9')
        define_custom_ciphersuite('DHE_PSK_WITH_AES_128_OCB_SHA256', 'FFFA')
        define_custom_ciphersuite('DHE_PSK_WITH_AES_256_OCB_SHA256', 'FFFB')

    if options.with_eax:
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_128_EAX_SHA256', 'FF90')
        define_custom_ciphersuite('ECDHE_ECDSA_WITH_AES_256_EAX_SHA384', 'FF91')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_128_EAX_SHA256', 'FF92')
        define_custom_ciphersuite('ECDHE_RSA_WITH_AES_256_EAX_SHA384', 'FF93')

    if options.with_srp_aead:
        define_custom_ciphersuite('SRP_SHA_WITH_AES_256_GCM_SHA384', 'FFA0')
        define_custom_ciphersuite('SRP_SHA_RSA_WITH_AES_256_GCM_SHA384', 'FFA1')
        define_custom_ciphersuite('SRP_SHA_DSS_WITH_AES_256_GCM_SHA384', 'FFA2')
        define_custom_ciphersuite('SRP_SHA_ECDSA_WITH_AES_256_GCM_SHA384', 'FFA3')

        if options.with_eax:
            define_custom_ciphersuite('SRP_SHA_WITH_AES_256_EAX_SHA384', 'FFA8')
            define_custom_ciphersuite('SRP_SHA_RSA_WITH_AES_256_EAX_SHA384', 'FFA9')
            define_custom_ciphersuite('SRP_SHA_DSS_WITH_AES_256_EAX_SHA384', 'FFAA')
            define_custom_ciphersuite('SRP_SHA_ECDSA_WITH_AES_256_EAX_SHA384', 'FFAB')

    suite_info = ''

    def header():
        return """/*
* TLS cipher suite information
*
* This file was automatically generated from the IANA assignments
* (tls-parameters.txt hash %s)
* by %s on %s
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

""" % (contents_hash, sys.argv[0], datetime.date.today().strftime("%Y-%m-%d"))

    suite_info += header()

    suite_info += """#include <botan/tls_ciphersuite.h>

namespace Botan {

namespace TLS {

std::vector<u16bit> Ciphersuite::all_known_ciphersuite_ids()
   {
   return std::vector<u16bit>{
"""

    for i in sorted(suites.keys()):
        suite_info += "      0x%s,\n" % (i)

    suite_info += """   };
}

Ciphersuite Ciphersuite::by_id(u16bit suite)
   {
   switch(suite)
      {
"""

    for i in sorted(suites.keys()):
        suite_name = suites[i][0]
        suite_expr = suites[i][1]
        suite_info += "      case 0x%s: // %s\n" % (i, suite_name)
        suite_info += "         return %s;\n\n" % (suite_expr)

    suite_info += """      }

   return Ciphersuite(); // some unknown ciphersuite
   }

}

}
"""

    if options.output == '-':
        print suite_info,
    else:
        out = open(options.output, 'w')
        out.write(suite_info)
        out.close()

if __name__ == '__main__':
    sys.exit(main())
