#!/usr/bin/env python

"""
(C) 2015,2017,2018 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import binascii
import botan2

def hex_encode(buf):
    return binascii.hexlify(buf).decode('ascii')

def hex_decode(buf):
    return binascii.unhexlify(buf.encode('ascii'))

def test():

    def test_version():

        print("\n%s" % botan2.version_string())
        print("v%d.%d.%d\n" % (botan2.version_major(), botan2.version_minor(), botan2.version_patch()))
        print("\nPython %s\n" % sys.version.replace('\n', ' '))

    def test_kdf():
        print("KDF2(SHA-1)   %s" %
              hex_encode(botan2.kdf('KDF2(SHA-1)',
                                    hex_decode('701F3480DFE95F57941F804B1B2413EF'), 7,
                                    hex_decode('55A4E9DD5F4CA2EF82'), hex_decode(''))))

    def test_pbkdf():
        print("PBKDF2(SHA-1) %s" %
              hex_encode(botan2.pbkdf('PBKDF2(SHA-1)', '', 32, 10000, hex_decode('0001020304050607'))[2]))
        print("good output   %s\n" %
              '59B2B1143B4CB1059EC58D9722FB1C72471E0D85C6F7543BA5228526375B0127')

        (salt, iterations, psk) = botan2.pbkdf_timed('PBKDF2(SHA-256)', 'xyz', 32, 200)

        print("PBKDF2(SHA-256) x=timed, y=iterated; salt = %s (len=%d)  #iterations = %d\n" %
              (hex_encode(salt), len(salt), iterations))

        print('x %s' % hex_encode(psk))
        print('y %s\n' % (hex_encode(botan2.pbkdf('PBKDF2(SHA-256)', 'xyz', 32, iterations, salt)[2])))

    def test_bcrypt():
        print("Testing Bcrypt...")
        r = botan2.rng()
        phash = botan2.bcrypt('testing', r)
        print("bcrypt returned %s (%d bytes)" % (hex_encode(phash), len(phash)))
        print("validating the hash produced: %r" % (botan2.check_bcrypt('testing', phash)))
        print("\n")

    def test_hmac():

        hmac = botan2.message_authentication_code('HMAC(SHA-256)')
        hmac.set_key(hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
        hmac.update(hex_decode('616263'))

        hmac_vec = hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181')
        hmac_output = hmac.final()

        if hmac_output != hmac_vec:
            print("Bad HMAC:\t%s" % hex_encode(hmac_output))
            print("vs good: \t%s" % hex_encode(hmac_vec))
        else:
            print("HMAC output correct: %s\n" % hex_encode(hmac_output))

    def test_rng():
        user_rng = botan2.rng("user")

        print("rng output:\n\t%s\n\t%s\n\t%s\n" %
              (hex_encode(user_rng.get(42)),
               hex_encode(user_rng.get(13)),
               hex_encode(user_rng.get(9))))

    def test_hash():
        md5 = botan2.hash_function('MD5')
        assert md5.output_length() == 16
        md5.update('h')
        md5.update('i')
        h1 = md5.final()
        print("md5 hash: %s (%s)\n" % (hex_encode(h1), '49f68a5c8493ec2c0bf489821c21fc3b'))

        md5.update(hex_decode('f468025b'))
        h2 = md5.final()
        print("md5 hash: %s (%s)\n" % (hex_encode(h2), '47efd2be302a937775e93dea281b6751'))

    def test_cipher():
        for mode in ['AES-128/CTR-BE', 'Serpent/GCM', 'ChaCha20Poly1305']:
            enc = botan2.cipher(mode, encrypt=True)

            (kmin, kmax) = enc.key_length()
            print("%s: default nonce=%d update_size=%d key_min=%d key_max=%d" %
                  (mode, enc.default_nonce_length(), enc.update_granularity(), kmin, kmax))

            rng = botan2.rng()
            iv = rng.get(enc.default_nonce_length())
            key = rng.get(kmax)
            pt = rng.get(21)

            print("  plaintext  %s (%d)"   % (hex_encode(pt), len(pt)))

            enc.set_key(key)
            enc.start(iv)

            update_result = enc.update('')
            assert not update_result

            ct = enc.finish(pt)
            print("  ciphertext %s (%d)" % (hex_encode(ct), len(ct)))

            dec = botan2.cipher(mode, encrypt=False)
            dec.set_key(key)
            dec.start(iv)
            decrypted = dec.finish(ct)

            print("  decrypted  %s (%d)\n" % (hex_encode(decrypted), len(decrypted)))


    def test_mceliece():
        mce_priv = botan2.private_key('mce', [2960, 57], botan2.rng())
        mce_pub = mce_priv.get_public_key()

        mce_plaintext = 'mce plaintext'
        mce_ad = 'mce AD'
        mce_ciphertext = botan2.mceies_encrypt(mce_pub, botan2.rng(), 'ChaCha20Poly1305', mce_plaintext, mce_ad)

        print("mceies len(pt)=%d  len(ct)=%d" % (len(mce_plaintext), len(mce_ciphertext)))

        mce_decrypt = botan2.mceies_decrypt(mce_priv, 'ChaCha20Poly1305', mce_ciphertext, mce_ad)
        print("  mceies plaintext  \'%s\' (%d)" % (mce_plaintext, len(mce_plaintext)))

        # Since mceies_decrypt() returns bytes in Python3, the following line
        # needs .decode('utf-8') to convert mce_decrypt from bytes to a
        # text string (Unicode).
        # You don't need to add .decode() if
        # (a) your expected output is bytes rather than a text string, or
        # (b) you are using Python2 rather than Python3.
        print("  mceies decrypted  \'%s\' (%d)" % (mce_decrypt.decode('utf-8'), len(mce_decrypt)))

        print("mce_pub %s/SHA-1 fingerprint: %s\nEstimated strength %s bits (len %d)\n" % (
            mce_pub.algo_name(), mce_pub.fingerprint("SHA-1"),
            mce_pub.estimated_strength(), len(mce_pub.encoding())
        ))

    def test_rsa():
        rsapriv = botan2.private_key('rsa', 1536, botan2.rng())
        rsapub = rsapriv.get_public_key()

        print("rsapub %s SHA-1 fingerprint: %s estimated strength %d (len %d)" % (
            rsapub.algo_name(), rsapub.fingerprint("SHA-1"),
            rsapub.estimated_strength(), len(rsapub.encoding())
        ))

        dec = botan2.pk_op_decrypt(rsapriv, "EME1(SHA-256)")
        enc = botan2.pk_op_encrypt(rsapub, "EME1(SHA-256)")

        sys_rng = botan2.rng()
        symkey = sys_rng.get(32)
        ctext = enc.encrypt(symkey, sys_rng)
        print("ptext   \'%s\' (%d)" % (hex_encode(symkey), len(symkey)))
        print("ctext   \'%s\' (%d)" % (hex_encode(ctext), len(ctext)))
        print("decrypt \'%s\' (%d)\n" % (hex_encode(dec.decrypt(ctext)),
                                         len(dec.decrypt(ctext))))

        signer = botan2.pk_op_sign(rsapriv, 'EMSA4(SHA-384)')

        signer.update('messa')
        signer.update('ge')
        sig = signer.finish(botan2.rng())

        print("EMSA4(SHA-384) signature: %s" % hex_encode(sig))

        verify = botan2.pk_op_verify(rsapub, 'EMSA4(SHA-384)')

        verify.update('mess')
        verify.update('age')
        print("good sig accepted? %s" % verify.check_signature(sig))

        verify.update('mess of things')
        verify.update('age')
        print("bad sig accepted?  %s" % verify.check_signature(sig))

        verify.update('message')
        print("good sig accepted? %s\n" % verify.check_signature(sig))

    def test_dh():
        a_rng = botan2.rng('user')
        b_rng = botan2.rng('user')

        for dh_grp in ['secp256r1', 'curve25519']:
            dh_kdf = 'KDF2(SHA-384)'.encode('utf-8')
            a_dh_priv = botan2.private_key('ecdh', dh_grp, botan2.rng())
            b_dh_priv = botan2.private_key('ecdh', dh_grp, botan2.rng())

            a_dh = botan2.pk_op_key_agreement(a_dh_priv, dh_kdf)
            b_dh = botan2.pk_op_key_agreement(b_dh_priv, dh_kdf)

            a_dh_pub = a_dh.public_value()
            b_dh_pub = b_dh.public_value()

            a_salt = a_rng.get(8)
            b_salt = b_rng.get(8)

            print("ecdh %s pubs:\n  %s (salt %s)\n  %s (salt %s)\n" %
                  (dh_grp,
                   hex_encode(a_dh_pub), hex_encode(a_salt),
                   hex_encode(b_dh_pub), hex_encode(b_salt)))

            a_key = a_dh.agree(b_dh_pub, 32, a_salt + b_salt)
            b_key = b_dh.agree(a_dh_pub, 32, a_salt + b_salt)

            print("ecdh %s shared:\n  %s\n  %s\n" %
                  (dh_grp, hex_encode(a_key), hex_encode(b_key)))

    def test_certs():
        cert = botan2.x509_cert(filename="src/tests/data/x509/ecc/CSCA.CSCA.csca-germany.1.crt")
        print("CSCA (Germany) Certificate\nDetails:")
        print("SHA-1 fingerprint:   %s" % cert.fingerprint("SHA-1"))
        print("Expected:            32:42:1C:C3:EC:54:D7:E9:43:EC:51:F0:19:23:BD:85:1D:F2:1B:B9")

        print("Not before:          %s" % cert.time_starts())
        print("Not after:           %s" % cert.time_expires())

        print("Serial number:       %s" % hex_encode(cert.serial_number()))
        print("Authority Key ID:    %s" % hex_encode(cert.authority_key_id()))
        print("Subject   Key ID:    %s" % hex_encode(cert.subject_key_id()))
        print("Public key bits:\n%s\n" % binascii.b2a_base64(cert.subject_public_key_bits()))

        pubkey = cert.subject_public_key()
        print("Public key algo:     %s" % pubkey.algo_name())
        print("Public key strength: %s" % pubkey.estimated_strength() + " bits")

        dn_fields = ("Name", "Email", "Organization", "Organizational Unit", "Country")
        for field in dn_fields:
            try:
                print("%s: %s" % (field, cert.subject_dn(field, 0)))
            except botan2.BotanException:
                print("Field: %s not found in certificate" % field)

        print(cert.to_string())

    test_version()
    test_kdf()
    test_pbkdf()
    test_bcrypt()
    test_hmac()
    test_rng()
    test_hash()
    test_cipher()
    test_mceliece()
    test_rsa()
    test_dh()
    test_certs()


def main(args=None):
    if args is None:
        args = sys.argv
    test()

if __name__ == '__main__':
    sys.exit(main())
