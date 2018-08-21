#!/usr/bin/env python

"""
(C) 2015,2017,2018 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import unittest
import binascii
import botan2

def hex_encode(buf):
    return binascii.hexlify(buf).decode('ascii')

def hex_decode(buf):
    return binascii.unhexlify(buf.encode('ascii'))

class BotanPythonTests(unittest.TestCase):

    def test_version(self):
        version_str = botan2.version_string()
        self.assertTrue(version_str.startswith('Botan '))

        self.assertEqual(botan2.version_major(), 2)
        self.assertTrue(botan2.version_minor() >= 8)

    def test_kdf(self):

        secret = hex_decode('6FD4C3C0F38E5C7A6F83E99CD9BD')
        salt = hex_decode('DBB986')
        label = hex_decode('')
        expected = hex_decode('02AEB40A3D4B66FBA540F9D4B20006F2046E0F3A029DEAB201FC692B79EB27CEF7E16069046A')

        produced = botan2.kdf('KDF2(SHA-1)', secret, 38, salt, label)

        self.assertEqual(hex_encode(produced), hex_encode(expected))

    def test_pbkdf(self):

        (salt, iterations, pbkdf) = botan2.pbkdf('PBKDF2(SHA-1)', '', 32, 10000, hex_decode('0001020304050607'))

        self.assertEqual(iterations, 10000)
        self.assertEqual(hex_encode(pbkdf),
                         '59b2b1143b4cb1059ec58d9722fb1c72471e0d85c6f7543ba5228526375b0127')

        (salt, iterations, pbkdf) = botan2.pbkdf_timed('PBKDF2(SHA-256)', 'xyz', 32, 200)

        cmp_pbkdf = botan2.pbkdf('PBKDF2(SHA-256)', 'xyz', 32, iterations, salt)[2]

        self.assertEqual(pbkdf, cmp_pbkdf)

    def test_scrypt(self):
        scrypt = botan2.scrypt(10, '', '', 16, 1, 1)
        self.assertEqual(hex_encode(scrypt), "77d6576238657b203b19")

        scrypt = botan2.scrypt(32, 'password', 'NaCl', 1024, 8, 16)
        self.assertEqual(hex_encode(scrypt), "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162")

    def test_bcrypt(self):
        r = botan2.rng()
        phash = botan2.bcrypt('testing', r)
        self.assertTrue(isinstance(phash, str))
        self.assertTrue(phash.startswith("$2a$"))

        self.assertTrue(botan2.check_bcrypt('testing', phash))
        self.assertFalse(botan2.check_bcrypt('live fire', phash))

        self.assertTrue(botan2.check_bcrypt('test', '$2a$04$wjen1fAA.UW6UxthpKK.huyOoxvCR7ATRCVC4CBIEGVDOCtr8Oj1C'))

    def test_mac(self):

        hmac = botan2.message_authentication_code('HMAC(SHA-256)')
        self.assertEqual(hmac.algo_name(), 'HMAC(SHA-256)')
        self.assertEqual(hmac.minimum_keylength(), 0)
        self.assertEqual(hmac.maximum_keylength(), 4096)
        hmac.set_key(hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
        hmac.update(hex_decode('616263'))

        expected = hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181')
        produced = hmac.final()

        self.assertEqual(hex_encode(expected), hex_encode(produced))

    def test_rng(self):
        user_rng = botan2.rng("user")

        output1 = user_rng.get(32)
        output2 = user_rng.get(32)

        self.assertEqual(len(output1), 32)
        self.assertEqual(len(output2), 32)
        self.assertNotEqual(output1, output2)

        output3 = user_rng.get(1021)
        self.assertEqual(len(output3), 1021)

        system_rng = botan2.rng('system')

        user_rng.reseed_from_rng(system_rng, 256)

        user_rng.add_entropy('seed material...')

    def test_hash(self):
        h = botan2.hash_function('SHA-256')
        self.assertEqual(h.algo_name(), 'SHA-256')
        assert h.output_length() == 32
        h.update('ignore this please')
        h.clear()
        h.update('a')
        h1 = h.final()

        self.assertEqual(hex_encode(h1), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")

        h.update(hex_decode('616263'))
        h2 = h.final()
        self.assertEqual(hex_encode(h2), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_cipher(self):
        for mode in ['AES-128/CTR-BE', 'Serpent/GCM', 'ChaCha20Poly1305']:
            enc = botan2.cipher(mode, encrypt=True)

            if mode == 'AES-128/CTR-BE':
                self.assertEqual(enc.algo_name(), 'CTR-BE(AES-128)')
            elif mode == 'Serpent/GCM':
                self.assertEqual(enc.algo_name(), 'Serpent/GCM(16)')
            else:
                self.assertEqual(enc.algo_name(), mode)

            (kmin, kmax) = enc.key_length()

            self.assertTrue(kmin <= kmax)

            rng = botan2.rng()
            iv = rng.get(enc.default_nonce_length())
            key = rng.get(kmax)
            pt = rng.get(21)

            enc.set_key(key)
            enc.start(iv)

            update_result = enc.update('')
            assert not update_result

            ct = enc.finish(pt)

            dec = botan2.cipher(mode, encrypt=False)
            dec.set_key(key)
            dec.start(iv)
            decrypted = dec.finish(ct)

            self.assertEqual(decrypted, pt)


    def test_mceliece(self):
        rng = botan2.rng()
        mce_priv = botan2.private_key('mce', [2960, 57], rng)
        mce_pub = mce_priv.get_public_key()
        self.assertEqual(mce_pub.estimated_strength(), 128)

        mce_plaintext = rng.get(16)
        mce_ad = rng.get(48)
        mce_ciphertext = botan2.mceies_encrypt(mce_pub, botan2.rng(), 'ChaCha20Poly1305', mce_plaintext, mce_ad)

        mce_decrypt = botan2.mceies_decrypt(mce_priv, 'ChaCha20Poly1305', mce_ciphertext, mce_ad)

        self.assertEqual(mce_plaintext, mce_decrypt)

    def test_rsa(self):
        rng = botan2.rng()
        rsapriv = botan2.private_key('RSA', '1024', rng)
        self.assertEqual(rsapriv.algo_name(), 'RSA')

        rsapub = rsapriv.get_public_key()
        self.assertEqual(rsapub.algo_name(), 'RSA')
        self.assertEqual(rsapub.estimated_strength(), 80)

        enc = botan2.pk_op_encrypt(rsapub, "OAEP(SHA-256)")
        dec = botan2.pk_op_decrypt(rsapriv, "OAEP(SHA-256)")

        symkey = rng.get(32)
        ctext = enc.encrypt(symkey, rng)

        ptext = dec.decrypt(ctext)

        self.assertEqual(ptext, symkey)

        signer = botan2.pk_op_sign(rsapriv, 'EMSA4(SHA-384)')

        signer.update('messa')
        signer.update('ge')
        sig = signer.finish(botan2.rng())

        verify = botan2.pk_op_verify(rsapub, 'EMSA4(SHA-384)')

        verify.update('mess')
        verify.update('age')
        self.assertTrue(verify.check_signature(sig))

        verify.update('mess of things')
        verify.update('age')
        self.assertFalse(verify.check_signature(sig))

        verify.update('message')
        self.assertTrue(verify.check_signature(sig))

    def test_dh(self):
        a_rng = botan2.rng('user')
        b_rng = botan2.rng('user')

        for dh_grp in ['secp256r1', 'curve25519']:
            dh_kdf = 'KDF2(SHA-384)'.encode('utf-8')
            a_dh_priv = botan2.private_key('ecdh', dh_grp, a_rng)
            b_dh_priv = botan2.private_key('ecdh', dh_grp, b_rng)

            a_dh = botan2.pk_op_key_agreement(a_dh_priv, dh_kdf)
            b_dh = botan2.pk_op_key_agreement(b_dh_priv, dh_kdf)

            a_dh_pub = a_dh.public_value()
            b_dh_pub = b_dh.public_value()

            salt = a_rng.get(8) + b_rng.get(8)

            a_key = a_dh.agree(b_dh_pub, 32, salt)
            b_key = b_dh.agree(a_dh_pub, 32, salt)

            self.assertEqual(a_key, b_key)

    def test_certs(self):
        cert = botan2.x509_cert(filename="src/tests/data/x509/ecc/CSCA.CSCA.csca-germany.1.crt")
        pubkey = cert.subject_public_key()

        self.assertEqual(pubkey.algo_name(), 'ECDSA')
        self.assertEqual(pubkey.estimated_strength(), 112)

        self.assertEqual(cert.fingerprint("SHA-1"),
                         "32:42:1C:C3:EC:54:D7:E9:43:EC:51:F0:19:23:BD:85:1D:F2:1B:B9")

        self.assertEqual(hex_encode(cert.serial_number()), "01")
        self.assertEqual(hex_encode(cert.authority_key_id()),
                         "0096452de588f966c4ccdf161dd1f3f5341b71e7")

        self.assertEqual(cert.subject_dn('Name', 0), 'csca-germany')
        self.assertEqual(cert.subject_dn('Email', 0), 'csca-germany@bsi.bund.de')
        self.assertEqual(cert.subject_dn('Organization', 0), 'bund')
        self.assertEqual(cert.subject_dn('Organizational Unit', 0), 'bsi')
        self.assertEqual(cert.subject_dn('Country', 0), 'DE')

        self.assertTrue(cert.to_string().startswith("Version: 3"))

    def test_mpi(self):
        # pylint: disable=too-many-statements
        z = botan2.MPI()
        self.assertEqual(z.bit_count(), 0)
        five = botan2.MPI('5')
        self.assertEqual(five.bit_count(), 3)
        big = botan2.MPI('0x85839682368923476892367235')
        self.assertEqual(big.bit_count(), 104)
        small = botan2.MPI(0xDEADBEEF)

        self.assertEqual(int(small), 0xDEADBEEF)

        self.assertEqual(int(small >> 16), 0xDEAD)

        small >>= 15

        self.assertEqual(int(small), 0x1BD5B)

        small <<= 15

        self.assertEqual(int(small), 0xDEAD8000)

        ten = botan2.MPI(10)

        self.assertEqual(ten, five + five)
        self.assertNotEqual(ten, five)
        self.assertTrue(five < ten)
        self.assertTrue(five <= ten)

        x = botan2.MPI(five)

        self.assertEqual(x, five)

        x += botan2.MPI(1)
        self.assertNotEqual(x, five)

        self.assertEqual(int(x * five), 30)

        x *= five
        x *= five
        self.assertEqual(int(x), 150)

        self.assertTrue(not x.is_negative())

        x.flip_sign()
        self.assertTrue(x.is_negative())
        self.assertEqual(int(x), -150)

        x.flip_sign()

        x.set_bit(0)
        self.assertTrue(int(x), 151)
        self.assertTrue(x.get_bit(0))
        self.assertTrue(x.get_bit(4))
        self.assertFalse(x.get_bit(6))

        x.clear_bit(4)
        self.assertEqual(int(x), 135)

        rng = botan2.RandomNumberGenerator()
        self.assertFalse(x.is_prime(rng))

        two = botan2.MPI(2)

        x += two
        self.assertTrue(x.is_prime(rng))

        mod = x + two

        inv = x.inverse_mod(mod)
        self.assertEqual(int(inv), 69)
        self.assertEqual(int((inv * x) % mod), 1)

        p = inv.pow_mod(botan2.MPI(46), mod)
        self.assertEqual(int(p), 42)

    def test_fpe(self):

        modulus = botan2.MPI('1000000000')
        key = b'001122334455'

        fpe = botan2.FormatPreservingEncryptionFE1(modulus, key)

        value = botan2.MPI('392910392')
        tweak = 'tweak value'

        ctext = fpe.encrypt(value, tweak)

        ptext = fpe.decrypt(ctext, tweak)

        self.assertEqual(value, ptext)

    def test_hotp(self):

        hotp = botan2.HOTP(b'12345678901234567890')

        self.assertEqual(hotp.generate(0), 755224)
        self.assertEqual(hotp.generate(1), 287082)
        self.assertEqual(hotp.generate(9), 520489)

        self.assertEqual(hotp.check(520489, 8), (False, 8))
        self.assertEqual(hotp.check(520489, 8, 1), (True, 10))
        self.assertEqual(hotp.check(520489, 7, 2), (True, 10))
        self.assertEqual(hotp.check(520489, 0, 9), (True, 10))


if __name__ == '__main__':
    unittest.main()
