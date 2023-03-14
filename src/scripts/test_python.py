#!/usr/bin/env python3

"""
(C) 2015,2017,2018,2019 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import unittest
import binascii
import os
import platform
import argparse
import sys
from itertools import permutations

# Starting with Python 3.8 DLL search locations are more restricted on Windows.
# Hence, we need to explicitly add the current working directory before trying
# to load the botan python wrapper.
# See: https://docs.python.org/3/whatsnew/3.8.html#bpo-36085-whatsnew
if platform.system() == "Windows" and hasattr(os, "add_dll_directory"):
    os.add_dll_directory(os.getcwd())

import botan3 as botan # pylint: disable=wrong-import-position

def hex_encode(buf):
    return binascii.hexlify(buf).decode('ascii')

def hex_decode(buf):
    return binascii.unhexlify(buf.encode('ascii'))

# pylint: disable=global-statement

TEST_DATA_DIR = '.'

def test_data(relpath):
    return os.path.join(TEST_DATA_DIR, relpath)

class BotanPythonTests(unittest.TestCase):
    # pylint: disable=too-many-public-methods,too-many-locals

    def test_version(self):
        version_str = botan.version_string()
        self.assertTrue(version_str.startswith('Botan '))

        self.assertEqual(botan.version_major(), 3)
        self.assertGreaterEqual(botan.version_minor(), 0)

        self.assertGreaterEqual(botan.ffi_api_version(), 20180713)

    def test_compare(self):

        x = "1234"
        y = "1234"
        z = "1233"
        self.assertTrue(botan.const_time_compare(x, y))
        self.assertFalse(botan.const_time_compare(x, z))
        self.assertFalse(botan.const_time_compare(x, x + z))

    def test_block_cipher(self):
        aes = botan.BlockCipher("AES-128")
        self.assertEqual(aes.algo_name(), "AES-128")
        self.assertEqual(aes.block_size(), 16)
        self.assertEqual(aes.minimum_keylength(), 16)
        self.assertEqual(aes.maximum_keylength(), 16)

        aes.set_key(hex_decode("000102030405060708090a0b0c0d0e0f"))
        ct = aes.encrypt(hex_decode("00112233445566778899aabbccddeeff"))

        self.assertEqual(hex_encode(ct), "69c4e0d86a7b0430d8cdb78070b4c55a")

        pt = aes.decrypt(ct)

        self.assertEqual(hex_encode(pt), "00112233445566778899aabbccddeeff")

    def test_kdf(self):

        secret = hex_decode('6FD4C3C0F38E5C7A6F83E99CD9BD')
        salt = hex_decode('DBB986')
        label = hex_decode('')
        expected = hex_decode('02AEB40A3D4B66FBA540F9D4B20006F2046E0F3A029DEAB201FC692B79EB27CEF7E16069046A')

        produced = botan.kdf('KDF2(SHA-1)', secret, 38, salt, label)

        self.assertEqual(hex_encode(produced), hex_encode(expected))

    def test_pbkdf(self):

        (salt, iterations, pbkdf) = botan.pbkdf('PBKDF2(SHA-1)', '', 32, 10000, hex_decode('0001020304050607'))

        self.assertEqual(iterations, 10000)
        self.assertEqual(hex_encode(pbkdf),
                         '59b2b1143b4cb1059ec58d9722fb1c72471e0d85c6f7543ba5228526375b0127')

        (salt, iterations, pbkdf) = botan.pbkdf_timed('PBKDF2(SHA-256)', 'xyz', 32, 200)

        cmp_pbkdf = botan.pbkdf('PBKDF2(SHA-256)', 'xyz', 32, iterations, salt)[2]

        self.assertEqual(pbkdf, cmp_pbkdf)

    def test_scrypt(self):
        scrypt = botan.scrypt(10, '', '', 16, 1, 1)
        self.assertEqual(hex_encode(scrypt), "77d6576238657b203b19")

        scrypt = botan.scrypt(32, 'password', 'NaCl', 1024, 8, 16)
        self.assertEqual(hex_encode(scrypt), "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162")

    def test_bcrypt(self):
        r = botan.RandomNumberGenerator()
        phash = botan.bcrypt('testing', r)
        self.assertTrue(isinstance(phash, str))
        self.assertTrue(phash.startswith("$2a$"))

        self.assertTrue(botan.check_bcrypt('testing', phash))
        self.assertFalse(botan.check_bcrypt('live fire', phash))

        self.assertTrue(botan.check_bcrypt('test', '$2a$04$wjen1fAA.UW6UxthpKK.huyOoxvCR7ATRCVC4CBIEGVDOCtr8Oj1C'))

    def test_mac(self):

        hmac = botan.MsgAuthCode('HMAC(SHA-256)')
        self.assertEqual(hmac.algo_name(), 'HMAC(SHA-256)')
        self.assertEqual(hmac.minimum_keylength(), 0)
        self.assertEqual(hmac.maximum_keylength(), 4096)
        hmac.set_key(hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
        hmac.update(hex_decode('616263'))

        expected = hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181')
        produced = hmac.final()

        self.assertEqual(hex_encode(expected), hex_encode(produced))

    def test_gmac(self):
        gmac = botan.MsgAuthCode('GMAC(AES-128)')
        self.assertEqual(gmac.algo_name(), 'GMAC(AES-128)')
        gmac.set_key(hex_decode('00000000000000000000000000000000'))
        gmac.set_nonce(hex_decode('000000000000000000000000'))

        expected = hex_decode('58E2FCCEFA7E3061367F1D57A4E7455A')

        produced = gmac.final()

        self.assertEqual(hex_encode(expected), hex_encode(produced))

    def test_rng(self):
        user_rng = botan.RandomNumberGenerator("user")

        output1 = user_rng.get(32)
        output2 = user_rng.get(32)

        self.assertEqual(len(output1), 32)
        self.assertEqual(len(output2), 32)
        self.assertNotEqual(output1, output2)

        output3 = user_rng.get(1021)
        self.assertEqual(len(output3), 1021)

        system_rng = botan.RandomNumberGenerator('system')

        user_rng.reseed_from_rng(system_rng, 256)

        user_rng.add_entropy('seed material...')

    def test_hash(self):

        try:
            _h = botan.HashFunction('NoSuchHash')
        except botan.BotanException as e:
            self.assertEqual(str(e), "botan_hash_init failed: -40 (Not implemented)")

        sha256 = botan.HashFunction('SHA-256')
        self.assertEqual(sha256.algo_name(), 'SHA-256')
        self.assertEqual(sha256.output_length(), 32)
        self.assertEqual(sha256.block_size(), 64)
        sha256.update('ignore this please')
        sha256.clear()
        sha256.update('a')
        hash1 = sha256.final()

        self.assertEqual(hex_encode(hash1), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")

        sha256.update(hex_decode('61'))
        sha256_2 = sha256.copy_state()
        sha256.update(hex_decode('6263'))
        h2 = sha256.final()
        self.assertEqual(hex_encode(h2), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

        self.assertEqual(hex_encode(sha256_2.final()), hex_encode(hash1))

    def test_cipher(self):
        for mode in ['AES-128/CTR-BE', 'Serpent/GCM', 'ChaCha20Poly1305', 'AES-128/CBC/PKCS7']:
            enc = botan.SymmetricCipher(mode, encrypt=True)

            if mode == 'AES-128/CTR-BE':
                self.assertEqual(enc.algo_name(), 'CTR-BE(AES-128)')
            elif mode == 'Serpent/GCM':
                self.assertEqual(enc.algo_name(), 'Serpent/GCM(16)')
            else:
                self.assertEqual(enc.algo_name(), mode)

            (kmin, kmax) = enc.key_length()

            self.assertLessEqual(kmin, kmax)

            rng = botan.RandomNumberGenerator()
            iv = rng.get(enc.default_nonce_length())
            key = rng.get(kmax)
            pt = rng.get(21)

            enc.set_key(key)
            enc.start(iv)

            update_result = enc.update('')
            assert not update_result

            ct = enc.finish(pt)

            dec = botan.SymmetricCipher(mode, encrypt=False)
            dec.set_key(key)
            dec.start(iv)
            decrypted = dec.finish(ct)

            self.assertEqual(decrypted, pt)


    def test_mceliece(self):
        rng = botan.RandomNumberGenerator()
        mce_priv = botan.PrivateKey.create('McEliece', '2960,57', rng)
        mce_pub = mce_priv.get_public_key()
        self.assertEqual(mce_pub.estimated_strength(), 128)

    def test_rsa_load_store(self):

        rsa_priv_pem = """-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALWtiBjcofJW/4+r
CIjQZn2V3yCYsNIBpMdVkNPr36FZ3ZHGSv2ggmCe+IWy0fTcBVyP+fo3HC8zmOC2
EsYDFRExyB2zIsjRXlPrVrTfcyXwUEaInLJQId5CguFrmyj1y7K43ezg+OTop39n
TyaukrciCSCh++Q/UQOanHnR8ctrAgMBAAECgYBPfKySgBmk31ZyA7k4rsFgye01
JEkcoNZ41iGG7ujJffl4maLew9a3MmZ2jI3azVbVMDMFPA5rQm5tRowBMYEJ5oBc
LP4AP41Lujfa+vua6l3t94bAV+CufZiY0297FcPbGqNu+xSQ2Bol2uHh9mrcgQUs
fevA50KOLR9hv4zH6QJBAPCOKiExONtVhJn8qVPCBlJ8Vjjnt9Uno5EzMBAKMbZi
OySkGwo9/9LUWO03r7tjrGSy5jJk+iOrcLeDl6zETfkCQQDBV6PpD/3ccQ1IfWcw
jG8yik0bIuXgrD0uW4g8Cvj+05wrv7RYPHuFtj3Rtb94YjtgYn7QvjH7y88XmTC4
2k2DAkEA4E9Ae7kBUoz42/odDswyxwHICMIRyoJu5Ht9yscmufH5Ql6AFFnhzf9S
eMjfZfY4j6G+Q6mjElXQAl+DtIdMSQJBAJzdMkuBggI8Zv6NYA9voThsJSsDIWcr
12epM9sjO+nkXizQmM2OJNnThkyDHRna+Tm2MBXEemFEdn06+ODBnWkCQQChAbG4
255RiCuYdrfiTPF/WLtvRyGd1LRwHcYIW4mJFPzxYAMTwQKbppLAnxw73vyef/zC
2BgXEW02tjRBtgZ+
-----END PRIVATE KEY-----
"""

        rsa_pub_pem = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1rYgY3KHyVv+PqwiI0GZ9ld8g
mLDSAaTHVZDT69+hWd2Rxkr9oIJgnviFstH03AVcj/n6NxwvM5jgthLGAxURMcgd
syLI0V5T61a033Ml8FBGiJyyUCHeQoLha5so9cuyuN3s4Pjk6Kd/Z08mrpK3Igkg
ofvkP1EDmpx50fHLawIDAQAB
-----END PUBLIC KEY-----
"""

        rsapriv = botan.PrivateKey.load(rsa_priv_pem)

        self.assertEqual(rsapriv.to_pem(), rsa_priv_pem)

        rsapub = rsapriv.get_public_key()
        self.assertEqual(rsapub.to_pem(), rsa_pub_pem)

        rsapub = botan.PublicKey.load(rsa_pub_pem)
        self.assertEqual(rsapub.to_pem(), rsa_pub_pem)

        n = 0xB5AD8818DCA1F256FF8FAB0888D0667D95DF2098B0D201A4C75590D3EBDFA159DD91C64AFDA082609EF885B2D1F4DC055C8FF9FA371C2F3398E0B612C603151131C81DB322C8D15E53EB56B4DF7325F05046889CB25021DE4282E16B9B28F5CBB2B8DDECE0F8E4E8A77F674F26AE92B7220920A1FBE43F51039A9C79D1F1CB6B # pylint: disable=line-too-long
        e = 0x10001

        rsapub2 = botan.PublicKey.load_rsa(n, e)
        self.assertEqual(rsapub2.to_pem(), rsa_pub_pem)

        self.assertEqual(rsapub2.get_field("n"), n)
        self.assertEqual(rsapub2.get_field("e"), e)

    def test_key_crypto(self):
        rng = botan.RandomNumberGenerator()
        priv = botan.PrivateKey.create('RSA', '1024', rng)
        passphrase = "super secret tell noone"

        for is_pem in [True, False]:
            ref_val = priv.export(is_pem)

            enc1 = priv.export_encrypted(passphrase, rng, is_pem, msec=10)
            dec1 = botan.PrivateKey.load(enc1, passphrase)
            self.assertEqual(dec1.export(is_pem), ref_val)

            pem2 = priv.export_encrypted(passphrase, rng, is_pem, msec=10, cipher="AES-128/SIV")
            dec2 = botan.PrivateKey.load(pem2, passphrase)
            self.assertEqual(dec2.export(is_pem), ref_val)

            pem3 = priv.export_encrypted(passphrase, rng, is_pem, msec=10, cipher="AES-128/GCM", pbkdf="Scrypt")
            dec3 = botan.PrivateKey.load(pem3, passphrase)
            self.assertEqual(dec3.export(is_pem), ref_val)

    def test_check_key(self):
        # valid (if rather small) RSA key
        n = 273279220906618527352827457840955116141
        e = 0x10001

        rng = botan.RandomNumberGenerator()

        rsapub = botan.PublicKey.load_rsa(n, e)
        self.assertTrue(rsapub.check_key(rng))

        # invalid
        try:
            rsapub = botan.PublicKey.load_rsa(n - 1, e)
        except botan.BotanException as e:
            self.assertEqual(str(e), "botan_pubkey_load_rsa failed: -1 (Invalid input): Invalid RSA public key parameters")

    def test_rsa(self):
        # pylint: disable=too-many-locals
        rng = botan.RandomNumberGenerator()
        rsapriv = botan.PrivateKey.create('RSA', '1024', rng)
        self.assertEqual(rsapriv.algo_name(), 'RSA')

        priv_pem = rsapriv.to_pem()
        priv_der = rsapriv.to_der()

        self.assertEqual(priv_pem[0:28], "-----BEGIN PRIVATE KEY-----\n")
        self.assertGreater(len(priv_pem), len(priv_der))

        rsapub = rsapriv.get_public_key()
        self.assertEqual(rsapub.algo_name(), 'RSA')
        self.assertEqual(rsapub.estimated_strength(), 80)

        pub_pem = rsapub.to_pem()
        pub_der = rsapub.to_der()

        self.assertEqual(pub_pem[0:27], "-----BEGIN PUBLIC KEY-----\n")
        self.assertGreater(len(pub_pem), len(pub_der))

        enc = botan.PKEncrypt(rsapub, "OAEP(SHA-256)")
        dec = botan.PKDecrypt(rsapriv, "OAEP(SHA-256)")

        symkey = rng.get(32)
        ctext = enc.encrypt(symkey, rng)

        ptext = dec.decrypt(ctext)

        self.assertEqual(ptext, symkey)

        signer = botan.PKSign(rsapriv, 'EMSA4(SHA-384)')

        signer.update('messa')
        signer.update('ge')
        sig = signer.finish(botan.RandomNumberGenerator())

        verify = botan.PKVerify(rsapub, 'EMSA4(SHA-384)')

        verify.update('mess')
        verify.update('age')
        self.assertTrue(verify.check_signature(sig))

        verify.update('mess of things')
        verify.update('age')
        self.assertFalse(verify.check_signature(sig))

        verify.update('message')
        self.assertTrue(verify.check_signature(sig))

        salt = b'saltyseawater'
        kem_e = botan.KemEncrypt(rsapub, 'KDF2(SHA-256)')
        (shared_key, encap_key) = kem_e.create_shared_key(rng, salt, 32)
        self.assertEqual(len(shared_key), 32)
        self.assertEqual(len(encap_key), 1024//8)

        kem_d = botan.KemDecrypt(rsapriv, 'KDF2(SHA-256)')
        shared_key_d = kem_d.decrypt_shared_key(salt, 32, encap_key)
        self.assertEqual(shared_key, shared_key_d)

    def test_kyber(self):
        rng = botan.RandomNumberGenerator()

        kyber_priv = botan.PrivateKey.create('Kyber', 'Kyber-1024-r3', rng)
        kyber_pub = kyber_priv.get_public_key()

        salt = rng.get(16)
        kem_e = botan.KemEncrypt(kyber_pub, 'KDF2(SHA-256)')
        (shared_key, encap_key) = kem_e.create_shared_key(rng, salt, 32)
        self.assertEqual(len(shared_key), 32)
        self.assertEqual(len(encap_key), 1568)

        kem_d = botan.KemDecrypt(kyber_priv, 'KDF2(SHA-256)')
        shared_key_d = kem_d.decrypt_shared_key(salt, 32, encap_key)
        self.assertEqual(shared_key, shared_key_d)

    def test_ecdsa(self):
        rng = botan.RandomNumberGenerator()

        hash_fn = 'EMSA1(SHA-256)'
        group = 'secp256r1'
        msg = 'test message'

        priv = botan.PrivateKey.create('ECDSA', group, rng)
        pub = priv.get_public_key()
        self.assertEqual(pub.get_field('public_x'), priv.get_field('public_x'))
        self.assertEqual(pub.get_field('public_y'), priv.get_field('public_y'))

        signer = botan.PKSign(priv, hash_fn, True)
        signer.update(msg)
        signature = signer.finish(rng)

        verifier = botan.PKVerify(pub, hash_fn)
        verifier.update(msg)
        #fails because DER/not-DER mismatch
        self.assertFalse(verifier.check_signature(signature))

        verifier = botan.PKVerify(pub, hash_fn, True)
        verifier.update(msg)
        self.assertTrue(verifier.check_signature(signature))

        pub_x = pub.get_field('public_x')
        pub_y = priv.get_field('public_y')
        pub2 = botan.PublicKey.load_ecdsa(group, pub_x, pub_y)
        verifier = botan.PKVerify(pub2, hash_fn, True)
        verifier.update(msg)
        self.assertTrue(verifier.check_signature(signature))

        priv2 = botan.PrivateKey.load_ecdsa(group, priv.get_field('x'))
        signer = botan.PKSign(priv2, hash_fn, True)
        # sign empty message
        signature = signer.finish(rng)

        # verify empty message
        self.assertTrue(verifier.check_signature(signature))

    def test_sm2(self):
        rng = botan.RandomNumberGenerator()

        hash_fn = 'EMSA1(SM3)'
        group = 'sm2p256v1'
        msg = 'test message'

        priv = botan.PrivateKey.create('SM2', group, rng)
        pub = priv.get_public_key()
        self.assertEqual(pub.get_field('public_x'), priv.get_field('public_x'))
        self.assertEqual(pub.get_field('public_y'), priv.get_field('public_y'))

        signer = botan.PKSign(priv, hash_fn)
        signer.update(msg)
        signature = signer.finish(rng)

        verifier = botan.PKVerify(pub, hash_fn)
        verifier.update(msg)
        self.assertTrue(verifier.check_signature(signature))

        pub_x = pub.get_field('public_x')
        pub_y = priv.get_field('public_y')
        pub2 = botan.PublicKey.load_sm2(group, pub_x, pub_y)
        verifier = botan.PKVerify(pub2, hash_fn)
        verifier.update(msg)
        self.assertTrue(verifier.check_signature(signature))

        priv2 = botan.PrivateKey.load_sm2(group, priv.get_field('x'))
        signer = botan.PKSign(priv2, hash_fn)
        # sign empty message
        signature = signer.finish(rng)

        # verify empty message
        self.assertTrue(verifier.check_signature(signature))

    def test_ecdh(self):
        # pylint: disable=too-many-locals
        a_rng = botan.RandomNumberGenerator('user')
        b_rng = botan.RandomNumberGenerator('user')

        kdf = 'KDF2(SHA-384)'

        for grp in ['secp256r1', 'secp384r1', 'brainpool256r1']:
            a_priv = botan.PrivateKey.create('ECDH', grp, a_rng)
            b_priv = botan.PrivateKey.create('ECDH', grp, b_rng)

            a_op = botan.PKKeyAgreement(a_priv, kdf)
            b_op = botan.PKKeyAgreement(b_priv, kdf)

            a_pubv = a_op.public_value()
            b_pubv = b_op.public_value()

            a_pub_pt = a_priv.get_public_key().get_public_point()
            b_pub_pt = b_priv.get_public_key().get_public_point()

            self.assertEqual(a_op.public_value(), a_pub_pt)
            self.assertEqual(b_op.public_value(), b_pub_pt)

            salt = a_rng.get(8) + b_rng.get(8)

            a_key = a_op.agree(b_pubv, 32, salt)
            b_key = b_op.agree(a_pubv, 32, salt)

            self.assertEqual(a_key, b_key)

            a_pem = a_priv.to_pem()

            a_priv_x = a_priv.get_field('x')

            new_a = botan.PrivateKey.load_ecdh(grp, a_priv_x)

            self.assertEqual(a_pem, new_a.to_pem())

    def test_certs(self):
        # pylint: disable=too-many-statements
        cert = botan.X509Cert(filename=test_data("src/tests/data/x509/ecc/CSCA.CSCA.csca-germany.1.crt"))
        pubkey = cert.subject_public_key()

        self.assertEqual(len(cert.subject_public_key_bits()), 275)

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

        self.assertEqual(cert.issuer_dn('Name', 0), 'csca-germany')
        self.assertEqual(cert.issuer_dn('Organization', 0), 'bund')
        self.assertEqual(cert.issuer_dn('Organizational Unit', 0), 'bsi')
        self.assertEqual(cert.issuer_dn('Country', 0), 'DE')

        self.assertTrue(cert.hostname_match('csca-germany'))
        self.assertFalse(cert.hostname_match('csca-slovakia'))

        self.assertEqual(cert.not_before(), 1184858838)
        self.assertEqual(cert.not_after(), 1831907880)

        self.assertTrue(cert.allowed_usage(["CRL_SIGN", "KEY_CERT_SIGN"]))
        self.assertTrue(cert.allowed_usage(["KEY_CERT_SIGN"]))
        self.assertFalse(cert.allowed_usage(["DIGITAL_SIGNATURE"]))
        self.assertFalse(cert.allowed_usage(["DIGITAL_SIGNATURE", "CRL_SIGN"]))

        root = botan.X509Cert(test_data("src/tests/data/x509/nist/root.crt"))

        int09 = botan.X509Cert(test_data("src/tests/data/x509/nist/test09/int.crt"))
        end09 = botan.X509Cert(test_data("src/tests/data/x509/nist/test09/end.crt"))
        self.assertEqual(end09.verify([int09], [root]), 2001)

        end04 = botan.X509Cert(test_data("src/tests/data/x509/nist/test04/end.crt"))
        int04_1 = botan.X509Cert(test_data("src/tests/data/x509/nist/test04/int1.crt"))
        int04_2 = botan.X509Cert(test_data("src/tests/data/x509/nist/test04/int2.crt"))
        self.assertEqual(end04.verify([int04_1, int04_2], [], test_data("src/tests/data/x509/nist/"), required_strength=80), 0)
        self.assertEqual(end04.verify([int04_1, int04_2], [], required_strength=80), 3000)
        self.assertEqual(end04.verify([int04_1, int04_2], [root], required_strength=80, hostname="User1-CP.02.01"), 0)
        self.assertEqual(end04.verify([int04_1, int04_2], [root], required_strength=80, hostname="invalid"), 4008)
        self.assertEqual(end04.verify([int04_1, int04_2], [root], required_strength=80, reference_time=1), 2000)

        self.assertEqual(botan.X509Cert.validation_status(0), 'Verified')
        self.assertEqual(botan.X509Cert.validation_status(3000), 'Certificate issuer not found')
        self.assertEqual(botan.X509Cert.validation_status(4008), 'Certificate does not match provided name')

        rootcrl = botan.X509CRL(test_data("src/tests/data/x509/nist/root.crl"))

        end01 = botan.X509Cert(test_data("src/tests/data/x509/nist/test01/end.crt"))
        self.assertEqual(end01.verify([], [root], required_strength=80, crls=[rootcrl]), 0)

        int20 = botan.X509Cert(test_data("src/tests/data/x509/nist/test20/int.crt"))
        end20 = botan.X509Cert(test_data("src/tests/data/x509/nist/test20/end.crt"))
        int20crl = botan.X509CRL(test_data("src/tests/data/x509/nist/test20/int.crl"))

        self.assertEqual(end20.verify([int20], [root], required_strength=80, crls=[int20crl, rootcrl]), 5000)
        self.assertEqual(botan.X509Cert.validation_status(5000), 'Certificate is revoked')

        int21 = botan.X509Cert(test_data("src/tests/data/x509/nist/test21/int.crt"))
        end21 = botan.X509Cert(test_data("src/tests/data/x509/nist/test21/end.crt"))
        int21crl = botan.X509CRL(test_data("src/tests/data/x509/nist/test21/int.crl"))
        self.assertEqual(end21.verify([int21], [root], required_strength=80, crls=[int21crl, rootcrl]), 5000)

        self.assertTrue(int20.is_revoked(rootcrl))
        self.assertFalse(int04_1.is_revoked(rootcrl))
        self.assertTrue(end21.is_revoked(int21crl))


    def test_mpi(self):
        # pylint: disable=too-many-statements,too-many-locals
        z = botan.MPI()
        self.assertEqual(z.bit_count(), 0)
        five = botan.MPI('5')
        self.assertEqual(five.bit_count(), 3)
        big = botan.MPI('0x85839682368923476892367235')
        self.assertEqual(big.bit_count(), 104)
        small = botan.MPI(0xDEADBEEF)
        radix = botan.MPI("DEADBEEF", 16)

        self.assertEqual(hex_encode(small.to_bytes()), "deadbeef")
        self.assertEqual(hex_encode(big.to_bytes()), "85839682368923476892367235")

        self.assertEqual(int(small), 0xDEADBEEF)
        self.assertEqual(int(radix), int(small))

        self.assertEqual(int(small >> 16), 0xDEAD)

        small >>= 15

        self.assertEqual(int(small), 0x1BD5B)

        small <<= 15

        self.assertEqual(int(small), 0xDEAD8000)

        ten = botan.MPI(10)

        self.assertEqual(ten, five + five)
        self.assertNotEqual(ten, five)
        self.assertLess(five, ten)
        self.assertLessEqual(five, ten)

        x = botan.MPI(five)

        self.assertEqual(x, five)

        x += botan.MPI(1)
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

        rng = botan.RandomNumberGenerator()
        self.assertFalse(x.is_prime(rng))

        two = botan.MPI(2)

        x += two
        self.assertTrue(x.is_prime(rng))

        mod = x + two

        inv = x.inverse_mod(mod)
        self.assertEqual(int(inv), 69)
        self.assertEqual(int((inv * x) % mod), 1)

        p = inv.pow_mod(botan.MPI(46), mod)
        self.assertEqual(int(p), 42)

        one = botan.MPI(1)
        twelve = botan.MPI("C", 16)
        eight = botan.MPI(8)

        mul = twelve.mod_mul(eight, inv)
        self.assertEqual(int(mul), 27)

        gcd = one.gcd(one)
        self.assertEqual(one, gcd)
        gcd = one.gcd(twelve)
        self.assertEqual(one, gcd)
        gcd = twelve.gcd(eight)
        self.assertEqual(4, int(gcd))

    def test_mpi_random(self):
        rng = botan.RandomNumberGenerator()

        u = botan.MPI.random(rng, 512)
        self.assertEqual(u.bit_count(), 512)

        l = u >> 32
        self.assertEqual(l.bit_count(), 512-32)

        for _i in range(10):
            x = botan.MPI.random_range(rng, l, u)
            self.assertLess(x, u)
            self.assertGreater(x, l)

    def test_fpe(self):

        modulus = botan.MPI('1000000000')
        key = b'001122334455'

        fpe = botan.FormatPreservingEncryptionFE1(modulus, key)

        value = botan.MPI('392910392')
        tweak = 'tweak value'

        ctext = fpe.encrypt(value, tweak)

        ptext = fpe.decrypt(ctext, tweak)

        self.assertEqual(value, ptext)

    def test_keywrap(self):
        key = hex_decode('00112233445566778899aabbccddeeff')
        kek = hex_decode('000102030405060708090a0b0c0d0e0f')

        wrapped = botan.nist_key_wrap(kek, key)
        self.assertEqual(hex_encode(wrapped), '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5')

        self.assertEqual(len(wrapped), 16+8)
        unwrapped = botan.nist_key_unwrap(kek, wrapped)
        self.assertEqual(hex_encode(unwrapped), '00112233445566778899aabbccddeeff')

    def test_hotp(self):

        hotp = botan.HOTP(b'12345678901234567890')

        self.assertEqual(hotp.generate(0), 755224)
        self.assertEqual(hotp.generate(1), 287082)
        self.assertEqual(hotp.generate(9), 520489)

        self.assertEqual(hotp.check(520489, 8), (False, 8))
        self.assertEqual(hotp.check(520489, 8, 1), (True, 10))
        self.assertEqual(hotp.check(520489, 7, 2), (True, 10))
        self.assertEqual(hotp.check(520489, 0, 9), (True, 10))

    def test_totp(self):

        totp = botan.TOTP(b'12345678901234567890', digest="SHA-1", digits=8)

        self.assertEqual(totp.generate(59), 94287082)
        self.assertEqual(totp.generate(1111111109), 7081804)
        self.assertEqual(totp.generate(1111111111), 14050471)
        self.assertEqual(totp.generate(1234567890), 89005924)
        self.assertEqual(totp.generate(1234567890), 89005924)
        self.assertEqual(totp.generate(2000000000), 69279037)

        self.assertTrue(totp.check(7081804, 1111111109))
        self.assertTrue(totp.check(7081804, 1111111109 - 29))
        self.assertFalse(totp.check(7081804, 1111111109 + 1))
        self.assertTrue(totp.check(7081804, 1111111109 + 30, 1))

    def test_srp6(self):
        identity = 'alice'
        password = 'password123'
        rng = botan.RandomNumberGenerator()
        group = 'modp/srp/1024'
        hash_fn = 'SHA-512'

        # Test successful authentication
        server = botan.Srp6ServerSession(group)
        salt = rng.get(24)
        verifier = botan.generate_srp6_verifier(identity, password, salt, group, hash_fn)
        b = server.step1(verifier, hash_fn, rng)
        (a, key_c) = botan.srp6_client_agree(identity, password, group, hash_fn, salt, b, rng)
        key_s = server.step2(a)
        self.assertEqual(key_c, key_s)


class BotanPythonZfecTests(unittest.TestCase):
    """
    Tests relating to the ZFEC bindings
    """

    def test_encode(self):
        """
        Simple encoder test.

        Could benefit from more variations
        """
        n = 3
        k = 2
        input_bytes = b"abcdefgh" + b"ijklmnop"
        output_shares = botan.zfec_encode(k, n, input_bytes)
        self.assertEqual(
            output_shares,
            [b'abcdefgh', b'ijklmnop', b'qrstuvwX']
        )

    def test_encode_decode(self):
        """
        Simple round-trip tests.
        """
        def byte_iter():
            b = 0
            while True:
                yield bytes([b])
                b = (b + 1) % 256

        random_bytes = byte_iter()

        for k in range(1, 5):
            for n in range(k, k + 5):
                for x in range(128, 256, 5):
                    input_bytes = b"".join([
                        next(random_bytes)
                        for _ in range(x * k)
                    ])
                    with self.subTest("encode_decode variant", n=n, k=k, size=x):
                        self._encode_decode_test(n, k, input_bytes)

    def _encode_decode_test(self, n, k, input_bytes):
        """
        one instance of a round-trip test
        """
        output_shares = botan.zfec_encode(k, n, input_bytes)
        # want to check that every permutation of the inputs decodes to the
        # correct input bytes

        for inputs in permutations(enumerate(output_shares), k):
            # "unzip" the enumerated permutation
            indexes, shares = zip(*inputs)
            decoded = botan.zfec_decode(k, n, indexes, shares)
            self.assertEqual(
                b"".join(decoded),
                input_bytes
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test-data-dir', default='.')
    parser.add_argument('unittest_args', nargs='*')

    args = parser.parse_args()
    global TEST_DATA_DIR
    TEST_DATA_DIR = args.test_data_dir

    sys.argv[1:] = args.unittest_args
    unittest.main()

if __name__ == '__main__':
    main()
