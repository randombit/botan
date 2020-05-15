#!/usr/bin/env python

"""
(C) 2015,2017,2018,2019 Jack Lloyd

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
    # pylint: disable=too-many-public-methods,too-many-locals

    def test_version(self):
        version_str = botan2.version_string()
        self.assertTrue(version_str.startswith('Botan '))

        self.assertEqual(botan2.version_major(), 2)
        self.assertGreaterEqual(botan2.version_minor(), 8)

        self.assertGreaterEqual(botan2.ffi_api_version(), 20180713)

    def test_compare(self):

        x = "1234"
        y = "1234"
        z = "1233"
        self.assertTrue(botan2.const_time_compare(x, y))
        self.assertFalse(botan2.const_time_compare(x, z))
        self.assertFalse(botan2.const_time_compare(x, x + z))

    def test_block_cipher(self):
        aes = botan2.BlockCipher("AES-128")
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
        r = botan2.RandomNumberGenerator()
        phash = botan2.bcrypt('testing', r)
        self.assertTrue(isinstance(phash, str))
        self.assertTrue(phash.startswith("$2a$"))

        self.assertTrue(botan2.check_bcrypt('testing', phash))
        self.assertFalse(botan2.check_bcrypt('live fire', phash))

        self.assertTrue(botan2.check_bcrypt('test', '$2a$04$wjen1fAA.UW6UxthpKK.huyOoxvCR7ATRCVC4CBIEGVDOCtr8Oj1C'))

    def test_mac(self):

        hmac = botan2.MsgAuthCode('HMAC(SHA-256)')
        self.assertEqual(hmac.algo_name(), 'HMAC(SHA-256)')
        self.assertEqual(hmac.minimum_keylength(), 0)
        self.assertEqual(hmac.maximum_keylength(), 4096)
        hmac.set_key(hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
        hmac.update(hex_decode('616263'))

        expected = hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181')
        produced = hmac.final()

        self.assertEqual(hex_encode(expected), hex_encode(produced))

    def test_rng(self):
        user_rng = botan2.RandomNumberGenerator("user")

        output1 = user_rng.get(32)
        output2 = user_rng.get(32)

        self.assertEqual(len(output1), 32)
        self.assertEqual(len(output2), 32)
        self.assertNotEqual(output1, output2)

        output3 = user_rng.get(1021)
        self.assertEqual(len(output3), 1021)

        system_rng = botan2.RandomNumberGenerator('system')

        user_rng.reseed_from_rng(system_rng, 256)

        user_rng.add_entropy('seed material...')

    def test_hash(self):

        try:
            _h = botan2.HashFunction('NoSuchHash')
        except botan2.BotanException as e:
            self.assertEqual(str(e), "botan_hash_init failed: -40 (Not implemented)")

        sha256 = botan2.HashFunction('SHA-256')
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
        for mode in ['AES-128/CTR-BE', 'Serpent/GCM', 'ChaCha20Poly1305']:
            enc = botan2.SymmetricCipher(mode, encrypt=True)

            if mode == 'AES-128/CTR-BE':
                self.assertEqual(enc.algo_name(), 'CTR-BE(AES-128)')
            elif mode == 'Serpent/GCM':
                self.assertEqual(enc.algo_name(), 'Serpent/GCM(16)')
            else:
                self.assertEqual(enc.algo_name(), mode)

            (kmin, kmax) = enc.key_length()

            self.assertLessEqual(kmin, kmax)

            rng = botan2.RandomNumberGenerator()
            iv = rng.get(enc.default_nonce_length())
            key = rng.get(kmax)
            pt = rng.get(21)

            enc.set_key(key)
            enc.start(iv)

            update_result = enc.update('')
            assert not update_result

            ct = enc.finish(pt)

            dec = botan2.SymmetricCipher(mode, encrypt=False)
            dec.set_key(key)
            dec.start(iv)
            decrypted = dec.finish(ct)

            self.assertEqual(decrypted, pt)


    def test_mceliece(self):
        rng = botan2.RandomNumberGenerator()
        mce_priv = botan2.PrivateKey.create('McEliece', '2960,57', rng)
        mce_pub = mce_priv.get_public_key()
        self.assertEqual(mce_pub.estimated_strength(), 128)

        mce_plaintext = rng.get(16)
        mce_ad = rng.get(48)
        mce_ciphertext = botan2.mceies_encrypt(mce_pub, rng, 'ChaCha20Poly1305', mce_plaintext, mce_ad)

        mce_decrypt = botan2.mceies_decrypt(mce_priv, 'ChaCha20Poly1305', mce_ciphertext, mce_ad)

        self.assertEqual(mce_plaintext, mce_decrypt)

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

        rsapriv = botan2.PrivateKey.load(rsa_priv_pem)

        self.assertEqual(rsapriv.to_pem(), rsa_priv_pem)

        rsapub = rsapriv.get_public_key()
        self.assertEqual(rsapub.to_pem(), rsa_pub_pem)

        rsapub = botan2.PublicKey.load(rsa_pub_pem)
        self.assertEqual(rsapub.to_pem(), rsa_pub_pem)

        n = 0xB5AD8818DCA1F256FF8FAB0888D0667D95DF2098B0D201A4C75590D3EBDFA159DD91C64AFDA082609EF885B2D1F4DC055C8FF9FA371C2F3398E0B612C603151131C81DB322C8D15E53EB56B4DF7325F05046889CB25021DE4282E16B9B28F5CBB2B8DDECE0F8E4E8A77F674F26AE92B7220920A1FBE43F51039A9C79D1F1CB6B # pylint: disable=line-too-long
        e = 0x10001

        rsapub2 = botan2.PublicKey.load_rsa(n, e)
        self.assertEqual(rsapub2.to_pem(), rsa_pub_pem)

        self.assertEqual(rsapub2.get_field("n"), n)
        self.assertEqual(rsapub2.get_field("e"), e)

    def test_key_crypto(self):
        rng = botan2.RandomNumberGenerator()
        priv = botan2.PrivateKey.create('RSA', '1024', rng)
        passphrase = "super secret tell noone"

        for is_pem in [True, False]:
            ref_val = priv.export(is_pem)

            enc1 = priv.export_encrypted(passphrase, rng, True, msec=10)
            dec1 = botan2.PrivateKey.load(enc1, passphrase)
            self.assertEqual(dec1.export(is_pem), ref_val)

            pem2 = priv.export_encrypted(passphrase, rng, True, msec=10, cipher="AES-128/SIV")
            dec2 = botan2.PrivateKey.load(pem2, passphrase)
            self.assertEqual(dec2.export(is_pem), ref_val)

            pem3 = priv.export_encrypted(passphrase, rng, True, msec=10, cipher="AES-128/GCM", pbkdf="Scrypt")
            dec3 = botan2.PrivateKey.load(pem3, passphrase)
            self.assertEqual(dec3.export(is_pem), ref_val)

    def test_check_key(self):
        # valid (if rather small) RSA key
        n = 273279220906618527352827457840955116141
        e = 0x10001

        rng = botan2.RandomNumberGenerator()

        rsapub = botan2.PublicKey.load_rsa(n, e)
        self.assertTrue(rsapub.check_key(rng))

        # invalid
        try:
            rsapub = botan2.PublicKey.load_rsa(n - 1, e)
        except botan2.BotanException as e:
            self.assertEqual(str(e), "botan_pubkey_load_rsa failed: -1 (Invalid input)")

    def test_rsa(self):
        # pylint: disable=too-many-locals
        rng = botan2.RandomNumberGenerator()
        rsapriv = botan2.PrivateKey.create('RSA', '1024', rng)
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

        enc = botan2.PKEncrypt(rsapub, "OAEP(SHA-256)")
        dec = botan2.PKDecrypt(rsapriv, "OAEP(SHA-256)")

        symkey = rng.get(32)
        ctext = enc.encrypt(symkey, rng)

        ptext = dec.decrypt(ctext)

        self.assertEqual(ptext, symkey)

        signer = botan2.PKSign(rsapriv, 'EMSA4(SHA-384)')

        signer.update('messa')
        signer.update('ge')
        sig = signer.finish(botan2.RandomNumberGenerator())

        verify = botan2.PKVerify(rsapub, 'EMSA4(SHA-384)')

        verify.update('mess')
        verify.update('age')
        self.assertTrue(verify.check_signature(sig))

        verify.update('mess of things')
        verify.update('age')
        self.assertFalse(verify.check_signature(sig))

        verify.update('message')
        self.assertTrue(verify.check_signature(sig))

    def test_ecdsa(self):
        rng = botan2.RandomNumberGenerator()

        hash_fn = 'EMSA1(SHA-256)'
        group = 'secp256r1'
        msg = 'test message'

        priv = botan2.PrivateKey.create('ECDSA', group, rng)
        pub = priv.get_public_key()
        self.assertEqual(pub.get_field('public_x'), priv.get_field('public_x'))
        self.assertEqual(pub.get_field('public_y'), priv.get_field('public_y'))

        signer = botan2.PKSign(priv, hash_fn, True)
        signer.update(msg)
        signature = signer.finish(rng)

        verifier = botan2.PKVerify(pub, hash_fn)
        verifier.update(msg)
        #fails because DER/not-DER mismatch
        self.assertFalse(verifier.check_signature(signature))

        verifier = botan2.PKVerify(pub, hash_fn, True)
        verifier.update(msg)
        self.assertTrue(verifier.check_signature(signature))

        pub_x = pub.get_field('public_x')
        pub_y = priv.get_field('public_y')
        pub2 = botan2.PublicKey.load_ecdsa(group, pub_x, pub_y)
        verifier = botan2.PKVerify(pub2, hash_fn, True)
        verifier.update(msg)
        self.assertTrue(verifier.check_signature(signature))

        priv2 = botan2.PrivateKey.load_ecdsa(group, priv.get_field('x'))
        signer = botan2.PKSign(priv2, hash_fn, True)
        # sign empty message
        signature = signer.finish(rng)

        # verify empty message
        self.assertTrue(verifier.check_signature(signature))

    def test_sm2(self):
        rng = botan2.RandomNumberGenerator()

        hash_fn = 'EMSA1(SM3)'
        group = 'sm2p256v1'
        msg = 'test message'

        priv = botan2.PrivateKey.create('SM2', group, rng)
        pub = priv.get_public_key()
        self.assertEqual(pub.get_field('public_x'), priv.get_field('public_x'))
        self.assertEqual(pub.get_field('public_y'), priv.get_field('public_y'))

        signer = botan2.PKSign(priv, hash_fn)
        signer.update(msg)
        signature = signer.finish(rng)

        verifier = botan2.PKVerify(pub, hash_fn)
        verifier.update(msg)
        self.assertTrue(verifier.check_signature(signature))

        pub_x = pub.get_field('public_x')
        pub_y = priv.get_field('public_y')
        pub2 = botan2.PublicKey.load_sm2(group, pub_x, pub_y)
        verifier = botan2.PKVerify(pub2, hash_fn)
        verifier.update(msg)
        self.assertTrue(verifier.check_signature(signature))

        priv2 = botan2.PrivateKey.load_sm2(group, priv.get_field('x'))
        signer = botan2.PKSign(priv2, hash_fn)
        # sign empty message
        signature = signer.finish(rng)

        # verify empty message
        self.assertTrue(verifier.check_signature(signature))

    def test_ecdh(self):
        # pylint: disable=too-many-locals
        a_rng = botan2.RandomNumberGenerator('user')
        b_rng = botan2.RandomNumberGenerator('user')

        kdf = 'KDF2(SHA-384)'

        for grp in ['secp256r1', 'secp384r1', 'brainpool256r1']:
            a_priv = botan2.PrivateKey.create('ECDH', grp, a_rng)
            b_priv = botan2.PrivateKey.create('ECDH', grp, b_rng)

            a_op = botan2.PKKeyAgreement(a_priv, kdf)
            b_op = botan2.PKKeyAgreement(b_priv, kdf)

            a_pub = a_op.public_value()
            b_pub = b_op.public_value()

            salt = a_rng.get(8) + b_rng.get(8)

            a_key = a_op.agree(b_pub, 32, salt)
            b_key = b_op.agree(a_pub, 32, salt)

            self.assertEqual(a_key, b_key)

            a_pem = a_priv.to_pem()

            a_priv_x = a_priv.get_field('x')

            new_a = botan2.PrivateKey.load_ecdh(grp, a_priv_x)

            self.assertEqual(a_pem, new_a.to_pem())

    def test_certs(self):
        # pylint: disable=too-many-statements
        cert = botan2.X509Cert(filename="src/tests/data/x509/ecc/CSCA.CSCA.csca-germany.1.crt")
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

        root = botan2.X509Cert("src/tests/data/x509/nist/root.crt")

        int09 = botan2.X509Cert("src/tests/data/x509/nist/test09/int.crt")
        end09 = botan2.X509Cert("src/tests/data/x509/nist/test09/end.crt")
        self.assertEqual(end09.verify([int09], [root]), 2001)

        end04 = botan2.X509Cert("src/tests/data/x509/nist/test04/end.crt")
        int04_1 = botan2.X509Cert("src/tests/data/x509/nist/test04/int1.crt")
        int04_2 = botan2.X509Cert("src/tests/data/x509/nist/test04/int2.crt")
        self.assertEqual(end04.verify([int04_1, int04_2], [], "src/tests/data/x509/nist/", required_strength=80), 0)
        self.assertEqual(end04.verify([int04_1, int04_2], [], required_strength=80), 3000)
        self.assertEqual(end04.verify([int04_1, int04_2], [root], required_strength=80, hostname="User1-CP.02.01"), 0)
        self.assertEqual(end04.verify([int04_1, int04_2], [root], required_strength=80, hostname="invalid"), 4008)
        self.assertEqual(end04.verify([int04_1, int04_2], [root], required_strength=80, reference_time=1), 2000)

        self.assertEqual(botan2.X509Cert.validation_status(0), 'Verified')
        self.assertEqual(botan2.X509Cert.validation_status(3000), 'Certificate issuer not found')
        self.assertEqual(botan2.X509Cert.validation_status(4008), 'Certificate does not match provided name')

        rootcrl = botan2.X509CRL("src/tests/data/x509/nist/root.crl")

        end01 = botan2.X509Cert("src/tests/data/x509/nist/test01/end.crt")
        self.assertEqual(end01.verify([], [root], required_strength=80, crls=[rootcrl]), 0)

        int20 = botan2.X509Cert("src/tests/data/x509/nist/test20/int.crt")
        end20 = botan2.X509Cert("src/tests/data/x509/nist/test20/end.crt")
        int20crl = botan2.X509CRL("src/tests/data/x509/nist/test20/int.crl")

        self.assertEqual(end20.verify([int20], [root], required_strength=80, crls=[int20crl, rootcrl]), 5000)
        self.assertEqual(botan2.X509Cert.validation_status(5000), 'Certificate is revoked')

        int21 = botan2.X509Cert("src/tests/data/x509/nist/test21/int.crt")
        end21 = botan2.X509Cert("src/tests/data/x509/nist/test21/end.crt")
        int21crl = botan2.X509CRL("src/tests/data/x509/nist/test21/int.crl")
        self.assertEqual(end21.verify([int21], [root], required_strength=80, crls=[int21crl, rootcrl]), 5000)

        self.assertTrue(int20.is_revoked(rootcrl))
        self.assertFalse(int04_1.is_revoked(rootcrl))
        self.assertTrue(end21.is_revoked(int21crl))


    def test_mpi(self):
        # pylint: disable=too-many-statements,too-many-locals
        z = botan2.MPI()
        self.assertEqual(z.bit_count(), 0)
        five = botan2.MPI('5')
        self.assertEqual(five.bit_count(), 3)
        big = botan2.MPI('0x85839682368923476892367235')
        self.assertEqual(big.bit_count(), 104)
        small = botan2.MPI(0xDEADBEEF)
        radix = botan2.MPI("DEADBEEF", 16)

        self.assertEqual(hex_encode(small.to_bytes()), "deadbeef")
        self.assertEqual(hex_encode(big.to_bytes()), "85839682368923476892367235")

        self.assertEqual(int(small), 0xDEADBEEF)
        self.assertEqual(int(radix), int(small))

        self.assertEqual(int(small >> 16), 0xDEAD)

        small >>= 15

        self.assertEqual(int(small), 0x1BD5B)

        small <<= 15

        self.assertEqual(int(small), 0xDEAD8000)

        ten = botan2.MPI(10)

        self.assertEqual(ten, five + five)
        self.assertNotEqual(ten, five)
        self.assertLess(five, ten)
        self.assertLessEqual(five, ten)

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

        one = botan2.MPI(1)
        twelve = botan2.MPI("C", 16)
        eight = botan2.MPI(8)

        mul = twelve.mod_mul(eight, inv)
        self.assertEqual(int(mul), 27)

        gcd = one.gcd(one)
        self.assertEqual(one, gcd)
        gcd = one.gcd(twelve)
        self.assertEqual(one, gcd)
        gcd = twelve.gcd(eight)
        self.assertEqual(4, int(gcd))

    def test_mpi_random(self):
        rng = botan2.RandomNumberGenerator()

        u = botan2.MPI.random(rng, 512)
        self.assertEqual(u.bit_count(), 512)

        l = u >> 32
        self.assertEqual(l.bit_count(), 512-32)

        for _i in range(10):
            x = botan2.MPI.random_range(rng, l, u)
            self.assertLess(x, u)
            self.assertGreater(x, l)

    def test_fpe(self):

        modulus = botan2.MPI('1000000000')
        key = b'001122334455'

        fpe = botan2.FormatPreservingEncryptionFE1(modulus, key)

        value = botan2.MPI('392910392')
        tweak = 'tweak value'

        ctext = fpe.encrypt(value, tweak)

        ptext = fpe.decrypt(ctext, tweak)

        self.assertEqual(value, ptext)

    def test_keywrap(self):
        key = hex_decode('00112233445566778899aabbccddeeff')
        kek = hex_decode('000102030405060708090a0b0c0d0e0f')

        wrapped = botan2.nist_key_wrap(kek, key)
        self.assertEqual(hex_encode(wrapped), '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5')

        self.assertEqual(len(wrapped), 16+8)
        unwrapped = botan2.nist_key_unwrap(kek, wrapped)
        self.assertEqual(hex_encode(unwrapped), '00112233445566778899aabbccddeeff')

    def test_hotp(self):

        hotp = botan2.HOTP(b'12345678901234567890')

        self.assertEqual(hotp.generate(0), 755224)
        self.assertEqual(hotp.generate(1), 287082)
        self.assertEqual(hotp.generate(9), 520489)

        self.assertEqual(hotp.check(520489, 8), (False, 8))
        self.assertEqual(hotp.check(520489, 8, 1), (True, 10))
        self.assertEqual(hotp.check(520489, 7, 2), (True, 10))
        self.assertEqual(hotp.check(520489, 0, 9), (True, 10))

    def test_totp(self):

        totp = botan2.TOTP(b'12345678901234567890', digest="SHA-1", digits=8)

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

if __name__ == '__main__':
    unittest.main()
