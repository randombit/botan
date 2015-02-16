#!/usr/bin/python

"""
Python wrapper of the botan crypto library
http://botan.randombit.net

(C) 2015 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
from ctypes import *

"""
Module initialization
"""
botan = CDLL('libbotan-1.11.so')

expected_api_rev = 20150210
botan_api_rev = botan.botan_ffi_api_version()

if botan_api_rev != expected_api_rev:
    raise Exception("Bad botan API rev got %d expected %d" % (botan_api_rev, expected_api_rev))

"""
Versions
"""
def version_major():
    return botan.botan_version_major()

def version_minor():
    return botan.botan_version_minor()

def version_patch():
    return botan.botan_version_patch()

def version_string():
    botan.botan_version_string.restype = c_char_p
    return botan.botan_version_string()

"""
RNG
"""
class rng(object):
    # Can also use type "system"
    def __init__(self, rng_type = 'system'):
        botan.botan_rng_init.argtypes = [c_void_p, c_char_p]
        self.rng = c_void_p(0)
        rc = botan.botan_rng_init(byref(self.rng), rng_type)
        if rc != 0 or self.rng is None:
            raise Exception("No rng " + algo + " for you!")

    def __del__(self):
        botan.botan_rng_destroy.argtypes = [c_void_p]
        botan.botan_rng_destroy(self.rng)

    def reseed(self, bits = 256):
        botan.botan_rng_reseed.argtypes = [c_void_p, c_size_t]
        botan.botan_rng_reseed(self.rng, bits)

    def get(self, length):
        botan.botan_rng_get.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        out = create_string_buffer(length)
        l = c_size_t(length)
        rc = botan.botan_rng_get(self.rng, out, l)
        return str(out.raw)

"""
Hash function
"""
class hash_function(object):
    def __init__(self, algo):
        botan.botan_hash_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = 0 # always zero in this API version
        self.hash = c_void_p(0)
        rc = botan.botan_hash_init(byref(self.hash), algo, flags)
        if rc != 0 or self.hash is None:
            raise Exception("No hash " + algo + " for you!")

    def __del__(self):
        botan.botan_hash_destroy.argtypes = [c_void_p]
        botan.botan_hash_destroy(self.hash)

    def clear(self):
        botan.botan_hash_clear.argtypes = [c_void_p]
        return botan.botan_hash_clear(self.hash)

    def output_length(self):
        botan.botan_hash_output_length.argtypes = [c_void_p,POINTER(c_size_t)]
        l = c_size_t(0)
        rc = botan.botan_hash_output_length(self.hash, byref(l))
        return l.value

    def update(self, x):
        botan.botan_hash_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_hash_update(self.hash, x, len(x))

    def final(self):
        botan.botan_hash_final.argtypes = [c_void_p, POINTER(c_char)]
        out = create_string_buffer(self.output_length())
        botan.botan_hash_final(self.hash, out)
        return str(out.raw)

"""
Message authentication codes
"""
class message_authentication_code(object):
    def __init__(self, algo):
        botan.botan_mac_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = 0 # always zero in this API version
        self.mac = c_void_p(0)
        rc = botan.botan_mac_init(byref(self.mac), algo, flags)
        if rc != 0 or self.hash is None:
            raise Exception("No mac " + algo + " for you!")

    def __del__(self):
        botan.botan_mac_destroy.argtypes = [c_void_p]
        botan.botan_mac_destroy(self.mac)

    def clear(self):
        botan.botan_mac_clear.argtypes = [c_void_p]
        return botan.botan_mac_clear(self.mac)

    def output_length(self):
        botan.botan_mac_output_length.argtypes = [c_void_p, POINTER(c_size_t)]
        l = c_size_t(0)
        rc = botan.botan_mac_output_length(self.mac, byref(l))
        return l.value

    def set_key(self, key):
        botan.botan_mac_set_key.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        return botan.botan_mac_set_key(self.mac, k, len(k))

    def update(self, x):
        botan.botan_mac_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_mac_update(self.mac, x, len(x))

    def final(self):
        botan.botan_mac_final.argtypes = [c_void_p, POINTER(c_char)]
        out = create_string_buffer(self.output_length())
        botan.botan_mac_final(self.mac, out)
        return str(out.raw)

class cipher(object):
    def __init__(self, algo, encrypt = True):
        botan.botan_cipher_init.argtypes = [c_void_p,c_char_p, c_uint32]
        flags = 0 if encrypt else 1
        self.cipher = c_void_p(0)
        rc = botan.botan_cipher_init(byref(self.cipher), algo, flags)
        if rc != 0 or self.cipher is None:
            raise Exception("No cipher " + algo + " for you!")

    def __del__(self):
        botan.botan_cipher_destroy.argtypes = [c_void_p]
        botan.botan_cipher_destroy(self.cipher)

    def default_nonce_length(self):
        botan.botan_cipher_default_nonce_length.argtypes = [c_void_p, POINTER(c_size_t)]
        l = c_size_t(0)
        botan.botan_cipher_default_nonce_length(self.cipher, byref(l))
        return l.value

    def update_granularity(self):
        botan.botan_cipher_update_granularity.argtypes = [c_void_p, POINTER(c_size_t)]
        l = c_size_t(0)
        botan.botan_cipher_update_granularity(self.cipher, byref(l))
        return l.value

    def tag_length(self):
        botan.botan_cipher_get_tag_length.argtypes = [c_void_p, POINTER(c_size_t)]
        l = c_size_t(0)
        botan.botan_cipher_get_tag_length(self.cipher, byref(l))
        return l.value

    def is_authenticated(self):
        return self.tag_length() > 0

    def valid_nonce_length(self, nonce_len):
        botan.botan_cipher_valid_nonce_length.argtypes = [c_void_p, c_size_t]
        rc = botan.botan_cipher_valid_nonce_length(self.cipher, nonce_len)
        if rc < 0:
            raise Exception('Error calling valid_nonce_length')
        return True if rc == 1 else False

    def clear(self):
        botan.botan_cipher_clear.argtypes = [c_void_p]
        botan.botan_cipher_clear(self.cipher)

    def set_key(self, key):
        botan.botan_cipher_set_key.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_cipher_set_key(self.cipher, key, len(key))


    def start(self, nonce):
        botan.botan_cipher_start.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_cipher_start(self.cipher, nonce, len(nonce))

    def _update(self, txt, final):
        botan.botan_cipher_update.argtypes = [c_void_p, c_uint32,
                                              POINTER(c_char), c_size_t, POINTER(c_size_t),
                                              POINTER(c_char), c_size_t, POINTER(c_size_t)]

        inp = txt if txt else ''
        inp_sz = c_size_t(len(inp))
        inp_consumed = c_size_t(0)
        out = create_string_buffer(inp_sz.value + (self.tag_length() if final else 0))
        out_sz = c_size_t(len(out))
        out_written = c_size_t(0)
        flags = c_uint32(1 if final else 0)

        botan.botan_cipher_update(self.cipher, flags,
                                  out, out_sz, byref(out_written),
                                  inp, inp_sz, byref(inp_consumed))

        # buffering not supported yet
        assert inp_consumed.value == inp_sz.value
        return out.raw[0:out_written.value]

    def update(self, txt):
        return self._update(txt, False)

    def finish(self, txt = None):
        return self._update(txt, True)


"""
Bcrypt
TODO: might not be enabled - handle that gracefully!
"""
def bcrypt(passwd, rng, work_factor = 10):
    botan.botan_bcrypt_generate.argtypes = [POINTER(c_char), POINTER(c_size_t),
                                            c_char_p, c_void_p, c_size_t, c_uint32]
    out_len = c_size_t(64)
    out = create_string_buffer(out_len.value)
    flags = c_uint32(0)
    rc = botan.botan_bcrypt_generate(out, byref(out_len), passwd, rng.rng, c_size_t(work_factor), flags)
    if rc != 0:
        raise Exception('botan bcrypt failed, error %s' % (rc))
    b = out.raw[0:out_len.value]
    if b[-1] == '\x00':
        b = b[:-1]
    return b

def check_bcrypt(passwd, bcrypt):
    rc = botan.botan_bcrypt_is_valid(passwd, bcrypt)
    return (rc == 0)

"""
PBKDF
"""
def pbkdf(algo, password, out_len, iterations = 10000, salt = rng().get(12)):
    botan.botan_pbkdf.argtypes = [c_char_p, POINTER(c_char), c_size_t, c_char_p, c_void_p, c_size_t, c_size_t]
    out_buf = create_string_buffer(out_len)
    botan.botan_pbkdf(algo, out_buf, out_len, password, salt, len(salt), iterations)
    return (salt,iterations,out_buf.raw)

def pbkdf_timed(algo, password, out_len, ms_to_run = 300, salt = rng().get(12))
    botan.botan_pbkdf_timed.argtypes = [c_char_p, POINTER(c_char), c_size_t, c_char_p,
                                        c_void_p, c_size_t, c_size_t, POINTER(c_size_t)]
    out_buf = create_string_buffer(out_len)
    iterations = c_size_t(0)
    botan.botan_pbkdf_timed(algo, out_buf, out_len, password, salt, len(salt), ms_to_run, byref(iterations))
    return (salt,iterations.value,out_buf.raw)

"""
KDF
"""
def kdf(algo, secret, out_len, salt):
    botan.botan_kdf.argtypes = [c_char_p, POINTER(c_char), c_size_t, POINTER(c_char), c_size_t, POINTER(c_char), c_size_t]
    out_buf = create_string_buffer(out_len)
    out_sz = c_size_t(out_len)
    botan.botan_kdf(algo, out_buf, out_sz, secret, len(secret), salt, len(salt))
    return out_buf.raw[0:out_sz.value]

"""
Public and private keys
"""
class public_key(object):
    def __init__(self, obj = c_void_p(0)):
        self.pubkey = obj

    def __del__(self):
        botan.botan_pubkey_destroy.argtypes = [c_void_p]
        botan.botan_pubkey_destroy(self.pubkey)

    def fingerprint(self, hash = 'SHA-256'):
        botan.botan_pubkey_fingerprint.argtypes = [c_void_p, c_char_p,
                                                   POINTER(c_char), POINTER(c_size_t)]

        n = hash_function(hash).output_length()
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)
        botan.botan_pubkey_fingerprint(self.pubkey, hash, buf, byref(buf_len))
        return buf[0:buf_len.value].encode('hex')

class private_key(object):
    def __init__(self, alg, param, rng):
        botan.botan_privkey_create_rsa.argtypes = [c_void_p, c_void_p, c_size_t]
        botan.botan_privkey_create_ecdsa.argtypes = [c_void_p, c_void_p, c_char_p]
        botan.botan_privkey_create_ecdh.argtypes = [c_void_p, c_void_p, c_char_p]

        self.privkey = c_void_p(0)
        if alg == 'rsa':
            botan.botan_privkey_create_rsa(byref(self.privkey), rng.rng, param)
        elif alg == 'ecdsa':
            botan.botan_privkey_create_ecdsa(byref(self.privkey), rng.rng, param)
        elif alg == 'ecdh':
            botan.botan_privkey_create_ecdh(byref(self.privkey), rng.rng, param)
        else:
            raise Exception('Unknown public key algo ' + alg)

        if self.privkey is None:
            raise Exception('Error creating ' + alg + ' key')

    def __del__(self):
        botan.botan_privkey_destroy.argtypes = [c_void_p]
        botan.botan_privkey_destroy(self.privkey)

    def get_public_key(self):
        botan.botan_privkey_export_pubkey.argtypes = [c_void_p, c_void_p]

        pub = c_void_p(0)
        botan.botan_privkey_export_pubkey(byref(pub), self.privkey)
        return public_key(pub)

    def export(self):
        botan.botan_privkey_export.argtypes = [c_void_p,POINTER(c_char),c_void_p]

        n = 4096
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)

        rc = botan.botan_privkey_export(self.privkey, buf, byref(buf_len))
        if rc != 0:
            buf = create_string_buffer(buf_len.value)
            botan.botan_privkey_export(self.privkey, buf, byref(buf_len))
        return buf[0:buf_len.value]


class pk_op_encrypt(object):
    def __init__(self, key, padding, rng):
        botan.botan_pk_op_encrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = 0 # always zero in this ABI
        botan.botan_pk_op_encrypt_create(byref(self.op), key.pubkey, padding, flags)
        if not self.op:
            raise Exception("No pk op for you")

    def __del__(self):
        botan.botan_pk_op_encrypt_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_encrypt_destroy(self.op)

    def encrypt(self, msg, rng):
        botan.botan_pk_op_encrypt.argtypes = [c_void_p, c_void_p,
                                              POINTER(c_char), POINTER(c_size_t),
                                              POINTER(c_char), c_size_t]

        outbuf_sz = c_size_t(4096) #?!?!
        outbuf = create_string_buffer(outbuf_sz.value)
        botan.botan_pk_op_encrypt(self.op, rng.rng, outbuf, byref(outbuf_sz), msg, len(msg))
        return outbuf.raw[0:outbuf_sz.value]

class pk_op_decrypt(object):
    def __init__(self, key, padding):
        botan.botan_pk_op_decrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = 0 # always zero in this ABI
        botan.botan_pk_op_decrypt_create(byref(self.op), key.privkey, padding, flags)
        if not self.op:
            raise Exception("No pk op for you")

    def __del__(self):
        botan.botan_pk_op_decrypt_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_decrypt_destroy(self.op)

    def decrypt(self, msg):
        botan.botan_pk_op_decrypt.argtypes = [c_void_p,
                                              POINTER(c_char), POINTER(c_size_t),
                                              POINTER(c_char), c_size_t]

        outbuf_sz = c_size_t(4096) #?!?!
        outbuf = create_string_buffer(outbuf_sz.value)
        botan.botan_pk_op_decrypt(self.op, outbuf, byref(outbuf_sz), msg, len(msg))
        return outbuf.raw[0:outbuf_sz.value]

class pk_op_sign(object):
    def __init__(self, key, padding):
        botan.botan_pk_op_sign_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = 0 # always zero in this ABI
        botan.botan_pk_op_sign_create(byref(self.op), key.privkey, padding, flags)
        if not self.op:
            raise Exception("No pk op for you")

    def __del__(self):
        botan.botan_pk_op_sign_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_sign_destroy(self.op)

    def update(self, msg):
        botan.botan_pk_op_sign_update.argtypes = [c_void_p,  POINTER(c_char), c_size_t]
        botan.botan_pk_op_sign_update(self.op, msg, len(msg))

    def finish(self, rng):
        botan.botan_pk_op_sign_finish.argtypes = [c_void_p, c_void_p, POINTER(c_char), POINTER(c_size_t)]
        outbuf_sz = c_size_t(4096) #?!?!
        outbuf = create_string_buffer(outbuf_sz.value)
        botan.botan_pk_op_sign_finish(self.op, rng.rng, outbuf, byref(outbuf_sz))
        return outbuf.raw[0:outbuf_sz.value]

class pk_op_verify(object):
    def __init__(self, key, padding):
        botan.botan_pk_op_verify_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = 0 # always zero in this ABI
        botan.botan_pk_op_verify_create(byref(self.op), key.pubkey, padding, flags)
        if not self.op:
            raise Exception("No pk op for you")

    def __del__(self):
        botan.botan_pk_op_verify_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_verify_destroy(self.op)

    def update(self, msg):
        botan.botan_pk_op_verify_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_pk_op_verify_update(self.op, msg, len(msg))

    def check_signature(self, signature):
        botan.botan_pk_op_verify_finish.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        rc = botan.botan_pk_op_verify_finish(self.op, signature, len(signature))
        if rc == 0:
            return True
        return False

class pk_op_key_agreement(object):
    def __init__(self, key, kdf):
        botan.botan_pk_op_key_agreement_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        botan.botan_pk_op_key_agreement_export_public.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        self.op = c_void_p(0)
        flags = 0 # always zero in this ABI
        botan.botan_pk_op_key_agreement_create(byref(self.op), key.privkey, kdf, flags)
        if not self.op:
            raise Exception("No key agreement for you")

        pub = create_string_buffer(4096)
        pub_len = c_size_t(len(pub))
        botan.botan_pk_op_key_agreement_export_public(key.privkey, pub, byref(pub_len))
        self.m_public_value = pub.raw[0:pub_len.value]

    def __del__(self):
        botan.botan_pk_op_key_agreement_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_key_agreement_destroy(self.op)

    def public_value(self):
        return self.m_public_value

    def agree(self, other, key_len, salt):
        botan.botan_pk_op_key_agreement.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t),
                                                    POINTER(c_char), c_size_t, POINTER(c_char), c_size_t]

        outbuf_sz = c_size_t(key_len)
        outbuf = create_string_buffer(outbuf_sz.value)
        rc = botan.botan_pk_op_key_agreement(self.op, outbuf, byref(outbuf_sz), other, len(other), salt, len(salt))

        if rc == -1 and outbuf_sz.value > len(outbuf):
            outbuf = create_string_buffer(outbuf_sz.value)
            botan.botan_pk_op_key_agreement(self.op, outbuf, byref(outbuf_sz), other, len(other), salt, len(salt))
        return outbuf.raw[0:outbuf_sz.value]

"""
Tests and examples
"""
def test():
    r = rng("user")


    print version_string()
    print version_major(), version_minor(), version_patch()


    print kdf('KDF2(SHA-1)', '701F3480DFE95F57941F804B1B2413EF'.decode('hex'), 7, '55A4E9DD5F4CA2EF82'.decode('hex')).encode('hex')

    print pbkdf('PBKDF2(SHA-1)', '', 32, 10000, '0001020304050607'.decode('hex')).encode('hex').upper()
    print '59B2B1143B4CB1059EC58D9722FB1C72471E0D85C6F7543BA5228526375B0127'

    (salt,iterations,psk) = pbkdf_timed('PBKDF2(SHA-256)', 'xyz', 32, r, 200, 12)
    print salt.encode('hex'), iterations
    print 'x', psk.encode('hex')
    print 'y', pbkdf('PBKDF2(SHA-256)', 'xyz', 32, iterations, salt).encode('hex')

    print r.get(42).encode('hex'), r.get(13).encode('hex'), r.get(9).encode('hex')

    h = hash_function('MD5')
    assert h.output_length() == 16
    h.update('h')
    h.update('i')
    print "md5", h.final().encode('hex')

    gcm = cipher('AES-128/GCM')
    gcm.set_key('00000000000000000000000000000000'.decode('hex'))
    gcm.start('000000000000000000000000'.decode('hex'))
    gcm.update('')
    gcm.update('')
    print 'gcm', gcm.finish('00000000000000000000000000000000'.decode('hex')).encode('hex')

    rsapriv = private_key('rsa', 1536, r)

    dec = pk_op_decrypt(rsapriv, "EME1(SHA-256)")

    rsapub = rsapriv.get_public_key()
    print rsapub.fingerprint("SHA-1")

    enc = pk_op_encrypt(rsapub, "EME1(SHA-256)", r)

    ctext = enc.encrypt('foof', r)
    print ctext.encode('hex')
    print dec.decrypt(ctext)

    signer = pk_op_sign(rsapriv, 'EMSA4(SHA-384)')

    signer.update('messa')
    signer.update('ge')
    sig = signer.finish(r)

    r.reseed(200)
    print sig.encode('hex')

    verify = pk_op_verify(rsapub, 'EMSA4(SHA-384)')

    verify.update('mess')
    verify.update('age')
    print "good sig accepted?", verify.check_signature(sig)

    verify.update('mess of things')
    verify.update('age')
    print "bad sig accepted?", verify.check_signature(sig)

    verify.update('message')
    print "good sig accepted?", verify.check_signature(sig)

    dh_grp = 'secp256r1'
    #dh_grp = 'curve25519'
    dh_kdf = 'KDF2(SHA-384)'
    a_dh_priv = private_key('ecdh', dh_grp, r)
    a_dh_pub = a_dh_priv.get_public_key()

    b_dh_priv = private_key('ecdh', dh_grp, r)
    b_dh_pub = b_dh_priv.get_public_key()

    a_dh = pk_op_key_agreement(a_dh_priv, dh_kdf)
    b_dh = pk_op_key_agreement(b_dh_priv, dh_kdf)

    print "dh pubs", a_dh.public_value().encode('hex'), b_dh.public_value().encode('hex')

    a_key = a_dh.agree(b_dh.public_value(), 20, 'salt')
    b_key = b_dh.agree(a_dh.public_value(), 20, 'salt')

    print "dh shared", a_key.encode('hex'), b_key.encode('hex')


    #f = open('key.ber','wb')
    #f.write(blob)
    #f.close()


def main(args = None):
    if args is None:
        args = sys.argv
    test()

if __name__ == '__main__':
    sys.exit(main())
