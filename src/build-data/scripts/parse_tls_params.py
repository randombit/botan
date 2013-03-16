#!/usr/bin/python

import sys, re

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
        'RC4': ('ARC4',None),
        'IDEA': ('IDEA',16),
        'DES': ('DES',8),
        '3DES': ('3DES',24),
        'CAMELLIA': ('Camellia',None),
        'AES': ('AES',None),
        'SEED': ('SEED',16),
        }

    tls_to_botan_names = {
        'anon': '',
        'MD5': 'MD5',
        'SHA': 'SHA-1',
        'SHA256': 'SHA-256',
        'SHA384': 'SHA-384',
        'SHA512': 'SHA-512',
        'RC4': 'ARC4',
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

    mac_algo = tls_to_botan_names[mac_algo]
    sig_algo = tls_to_botan_names[sig_algo]
    kex_algo = tls_to_botan_names[kex_algo]

    (cipher_algo, cipher_keylen) = cipher_info[cipher[0]]
    if cipher_keylen is None:
        cipher_keylen = int(cipher[1]) / 8

    if cipher_algo in ['AES', 'Camellia']:
        cipher_algo += '-%d' % (cipher_keylen*8)

    return 'Ciphersuite(0x%s, "%s", "%s", "%s", "%s", %d)' % (
        code, sig_algo, kex_algo, mac_algo, cipher_algo, cipher_keylen)

def main(args = None):
    if args is None:
        args = sys.argv

    # http://www.iana.org/assignments/tls-parameters/tls-parameters.txt
    input = open('tls-parameters.txt')

    ciphersuite_re = re.compile(' +0x([0-9a-fA-F][0-9a-fA-F]),0x([0-9a-fA-F][0-9a-fA-F]) + TLS_([A-Za-z_0-9]+) ')

    suites = {}
    suite_codes = {}

    for line in input:
        match = ciphersuite_re.match(line)
        if match:
            code = match.group(1) + match.group(2)
            name = match.group(3)

            not_supported = ['SCSV', 'KRB5', 'EXPORT', 'RC2', '_DES_', 'WITH_NULL',
                             'ECDH_ECDSA', 'ECDH_RSA', 'DH_DSS', 'DH_RSA',
                             'RSA_PSK', 'GCM', 'CCM', 'ARIA', 'IDEA']

            should_use = True
            for ns in not_supported:
                if ns in name:
                    should_use = False

            if should_use:
                suites[name] = (code,to_ciphersuite_info(code, name))

    # From http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01
    suites['DHE_DSS_WITH_RC4_128_SHA'] = ('0066', to_ciphersuite_info('0066', 'DHE_DSS_WITH_RC4_128_SHA'))

    for k in sorted(suites.keys()):
        print "      case 0x%s: // %s" % (suites[k][0], k)
        print "         return %s;" % (suites[k][1])
        print

    #print "return std::vector<u16bit>({"
    #for k in sorted([k[0] for k in suites.values()]):
    #    print "0x%s, " % (k),
    #print "});"

if __name__ == '__main__':
    sys.exit(main())
