#!/usr/bin/env python

"""
Python wrapper of the botan crypto library
http://botan.randombit.net

(C) 2015 Jack Lloyd
(C) 2015 Uri  Blumenthal (extensions and patches)

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
from ctypes import *
from binascii import hexlify, unhexlify
import base64

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
        if sys.version_info[0] < 3:
            rc = botan.botan_rng_init(byref(self.rng), rng_type)
        else:
            rc = botan.botan_rng_init(byref(self.rng), rng_type.encode('ascii'))
                
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
        if sys.version_info[0] < 3:
            return str(out.raw)
        else:
            return out.raw

"""
Hash function
"""
class hash_function(object):
    def __init__(self, algo):
        botan.botan_hash_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = c_uint32(0) # always zero in this API version
        self.hash = c_void_p(0)
        if sys.version_info[0] < 3:
            rc = botan.botan_hash_init(byref(self.hash), algo, flags)
        else:
            rc = botan.botan_hash_init(byref(self.hash), algo.encode('utf-8'), flags)
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
        if sys.version_info[0] < 3:
            return str(out.raw)
        else:
            return out.raw

"""
Message authentication codes
"""
class message_authentication_code(object):
    def __init__(self, algo):
        botan.botan_mac_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = c_uint32(0) # always zero in this API version
        self.mac = c_void_p(0)
        rc = botan.botan_mac_init(byref(self.mac), algo, flags)
        if rc != 0 or self.mac is None:
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
        return botan.botan_mac_set_key(self.mac, key, len(key))

    def update(self, x):
        botan.botan_mac_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_mac_update(self.mac, x, len(x))

    def final(self):
        botan.botan_mac_final.argtypes = [c_void_p, POINTER(c_char)]
        out = create_string_buffer(self.output_length())
        botan.botan_mac_final(self.mac, out)
        if sys.version_info[0] < 3:
            return str(out.raw)
        else:
            return out.raw

class cipher(object):
    def __init__(self, algo, encrypt = True):
        botan.botan_cipher_init.argtypes = [c_void_p,c_char_p, c_uint32]
        flags = 0 if encrypt else 1
        self.cipher = c_void_p(0)
        if sys.version_info[0] < 3:
            rc = botan.botan_cipher_init(byref(self.cipher), algo, flags)
        else:
            rc = botan.botan_cipher_init(byref(self.cipher), algo.encode('utf-8'), flags)
        if rc != 0 or self.cipher is None:
            raise Exception("No cipher " + algo + " for you!")

    def __del__(self):
        botan.botan_cipher_destroy.argtypes = [c_void_p]
        botan.botan_cipher_destroy(self.cipher)

    def default_nonce_length(self):
        botan.botan_cipher_get_default_nonce_length.argtypes = [c_void_p, POINTER(c_size_t)]
        l = c_size_t(0)
        botan.botan_cipher_get_default_nonce_length(self.cipher, byref(l))
        return l.value

    def update_granularity(self):
        botan.botan_cipher_get_update_granularity.argtypes = [c_void_p, POINTER(c_size_t)]
        l = c_size_t(0)
        botan.botan_cipher_get_update_granularity(self.cipher, byref(l))
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

    def set_assoc_data(self, ad):
        botan.botan_cipher_set_associated_data.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_cipher_set_associated_data(self.cipher, ad, len(ad))

    def start(self, nonce):
        botan.botan_cipher_start.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_cipher_start(self.cipher, nonce, len(nonce))

    def _update(self, txt, final):
        botan.botan_cipher_update.argtypes = [c_void_p, c_uint32,
                                              POINTER(c_char), c_size_t, POINTER(c_size_t),
                                              POINTER(c_char), c_size_t, POINTER(c_size_t)]

        inp = txt if txt else ''
        inp_sz = c_size_t(len(inp))
        if sys.version_info[0] >= 3:
            inp = cast(inp, c_char_p)
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

def pbkdf_timed(algo, password, out_len, ms_to_run = 300, salt = rng().get(12)):
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

    def estimated_strength(self):
        botan.botan_pubkey_estimated_strength.argtypes = [c_void_p, POINTER(c_size_t)]
        r = c_size_t(0)
        botan.botan_pubkey_estimated_strength(self.pubkey, byref(r))
        return r.value

    def algo_name(self):
        botan.botan_pubkey_algo_name.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]

        buf = create_string_buffer(64)
        buf_len = c_size_t(len(buf))
        botan.botan_pubkey_algo_name(self.pubkey, buf, byref(buf_len))
        assert buf_len.value <= len(buf)
        return buf.raw[0:buf_len.value]

    def fingerprint(self, hash = 'SHA-256'):
        botan.botan_pubkey_fingerprint.argtypes = [c_void_p, c_char_p,
                                                   POINTER(c_char), POINTER(c_size_t)]

        n = hash_function(hash).output_length()
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)
        if sys.version_info[0] > 2:
            hash = hash.encode('utf-8')
    
        botan.botan_pubkey_fingerprint(self.pubkey, hash, buf, byref(buf_len))
        return hexlify(buf[0:buf_len.value])

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
    def __init__(self, key, padding):
        botan.botan_pk_op_encrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        if sys.version_info[0] > 2:
            padding = cast(padding, c_char_p)
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
        ll = len(msg)
        #print("encrypt: len=%d" % ll)
        if sys.version_info[0] > 2:
            msg = cast(msg, c_char_p)
            ll = c_size_t(ll)
        botan.botan_pk_op_encrypt(self.op, rng.rng, outbuf, byref(outbuf_sz), msg, ll)
        #print("encrypt: outbuf_sz.value=%d" % outbuf_sz.value)
        return outbuf.raw[0:outbuf_sz.value]

    
class pk_op_decrypt(object):
    def __init__(self, key, padding):
        botan.botan_pk_op_decrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        if sys.version_info[0] > 2:
            padding = cast(padding, c_char_p)
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
        ll = len(msg)
        if sys.version_info[0] > 2:
            msg = cast(msg, c_char_p)
            ll  = c_size_t(ll)
        botan.botan_pk_op_decrypt(self.op, outbuf, byref(outbuf_sz), msg, ll)
        return outbuf.raw[0:outbuf_sz.value]

class pk_op_sign(object):
    def __init__(self, key, padding):
        botan.botan_pk_op_sign_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        if sys.version_info[0] > 2:
            padding = cast(padding, c_char_p)
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
        flags = c_uint32(0) # always zero in this ABI
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
        flags = c_uint32(0) # always zero in this ABI
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
        rc = botan.botan_pk_op_key_agreement(self.op, outbuf, byref(outbuf_sz),
                                             other, len(other), salt, len(salt))

        if rc == -1 and outbuf_sz.value > len(outbuf):
            outbuf = create_string_buffer(outbuf_sz.value)
            botan.botan_pk_op_key_agreement(self.op, outbuf, byref(outbuf_sz),
                                            other, len(other), salt, len(salt))
        return outbuf.raw[0:outbuf_sz.value]

"""
Tests and examples
"""
def test():
    r = rng("user")


    print("\n%s" % version_string().decode('utf-8'))
    print("v%d.%d.%d\n" % (version_major(), version_minor(), version_patch()))


    print("KDF2(SHA-1)   %s" %
          base64.b16encode(kdf('KDF2(SHA-1)'.encode('ascii'), unhexlify('701F3480DFE95F57941F804B1B2413EF'), 7,
                      unhexlify('55A4E9DD5F4CA2EF82'))
          ).decode('ascii')
    )

    print("PBKDF2(SHA-1) %s" %
          hexlify(pbkdf('PBKDF2(SHA-1)'.encode('ascii'), ''.encode('ascii'), 32, 10000,
                        unhexlify('0001020304050607'))
                  [2]
          ).upper().decode('ascii'))
    print("good output   %s\n" %
          '59B2B1143B4CB1059EC58D9722FB1C72471E0D85C6F7543BA5228526375B0127')


        
    (salt,iterations,psk) = pbkdf_timed('PBKDF2(SHA-256)'.encode('ascii'),
                                        'xyz'.encode('utf-8'), 32, 200)

    if sys.version_info[0] < 3:        
        print("PBKDF2(SHA-256) x=timed, y=iterated; salt = %s (len=%d)  #iterations = %d\n" %
              (hexlify(salt), len(salt), iterations)   )
    else:
        print("PBKDF2(SHA-256) x=timed, y=iterated; salt = %s (len=%d)  #iterations = %d\n" %
              (base64.b16encode(salt).decode('ascii'), len(salt), iterations)   )
        
    print('x %s' % hexlify(psk).decode('utf-8'))
    print('y %s\n' %
          (hexlify(pbkdf('PBKDF2(SHA-256)'.encode('utf-8'),
                         'xyz'.encode('ascii'), 32, iterations, salt)[2]).decode('utf-8')))

    hmac = message_authentication_code('HMAC(SHA-256)'.encode('ascii'))
    hmac.set_key(unhexlify('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
    hmac.update(unhexlify('616263'))
    
    hmac_output = hmac.final()

    if hmac_output != unhexlify('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181'):
        print("Bad HMAC:\t%s" % hexlify(bytes(hmac_output, 'utf-8')).decode('utf-8'))
        print("vs good: \tA21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181");
    else:
        print("HMAC output (good): %s\n" % hexlify(hmac_output).decode('utf-8'))
    
    print("rng output:\n\t%s\n\t%s\n\t%s\n" %
          (hexlify(r.get(42)).decode('utf-8'),
           hexlify(r.get(13)).decode('utf-8'),
           hexlify(r.get(9)).decode('utf-8')
          )
    )

    h = hash_function('MD5')
    assert h.output_length() == 16
    h.update('h'.encode('utf-8'))
    h.update('i'.encode('utf-8'))
    print("md5 hash: %s\n" % (hexlify(h.final())).decode('utf-8'))


    gcm = cipher('AES-128/GCM')
    print("AES-128/GCM: default nonce=%d update_size=%d" %
          (gcm.default_nonce_length(), gcm.update_granularity()))
    gcm_dec = cipher('AES-128/GCM', encrypt=False)

    iv = r.get(12)
    key = r.get(16)
    pt = r.get(21)
    gcm.set_key(key)
    gcm.start(iv)
    assert len(gcm.update('')) == 0
    ct = gcm.finish(pt)
    print("GCM ct %s" % hexlify(ct).decode('utf-8'))

    gcm_dec.set_key(key)
    gcm_dec.start(iv)
    dec = gcm_dec.finish(ct)
    print("GCM pt %s %d"   % (hexlify(pt).decode('utf-8'),   len(pt)))
    print("GCM de %s %d\n" % (hexlify(dec).decode('utf-8'), len(dec)))

    ocb = cipher('AES-128/OCB')
    print("AES-128/OCB: default nonce=%d update_size=%d" %
          (ocb.default_nonce_length(), ocb.update_granularity()))
    ocb_dec = cipher('AES-128/OCB', encrypt=False)

    iv = r.get(12)
    key = r.get(16)
    pt = r.get(21)
    ocb.set_key(key)
    ocb.start(iv)
    assert len(ocb.update('')) == 0
    ct = ocb.finish(pt)
    print("OCB ct %s" % hexlify(ct).decode('utf-8'))

    ocb_dec.set_key(key)
    ocb_dec.start(iv)
    dec = ocb_dec.finish(ct)
    print("OCB pt %s %d"   % (hexlify(pt).decode('utf-8'),  len(pt)))
    print("OCB de %s %d\n" % (hexlify(dec).decode('utf-8'), len(dec)))

    rsapriv = private_key('rsa', 1536, r)

    rsapub = rsapriv.get_public_key()
    
    print("rsapub %s/SHA-1 fingerprint: %s (estimated strength %s)" %
          (rsapub.algo_name().decode('utf-8'), rsapub.fingerprint("SHA-1").decode('utf-8'),
           rsapub.estimated_strength()
          )
    )

    dec = pk_op_decrypt(rsapriv, "EME1(SHA-256)".encode('utf-8'))
    enc = pk_op_encrypt(rsapub, "EME1(SHA-256)".encode('utf-8'))

    ctext = enc.encrypt('foof'.encode('utf-8'), r)
    print("ptext  \'%s\'" % 'foof') 
    print("ctext   \'%s\'" % hexlify(ctext).decode('utf-8'))
    print("decrypt \'%s\'\n" % dec.decrypt(ctext).decode('utf-8'))

    signer = pk_op_sign(rsapriv, 'EMSA4(SHA-384)'.encode('utf-8'))

    signer.update('messa'.encode('utf-8'))
    signer.update('ge'.encode('utf-8'))
    sig = signer.finish(r)

    r.reseed(200)
    print("EMSA4(SHA-384) signature: %s" % hexlify(sig).decode('utf-8'))

    
    verify = pk_op_verify(rsapub, 'EMSA4(SHA-384)'.encode('utf-8'))

    verify.update('mess'.encode('utf-8'))
    verify.update('age'.encode('utf-8'))
    print("good sig accepted? %s" % verify.check_signature(sig))

    verify.update('mess of things'.encode('utf-8'))
    verify.update('age'.encode('utf-8'))
    print("bad sig accepted? %s" % verify.check_signature(sig))

    verify.update('message'.encode('utf-8'))
    print("good sig accepted? %s\n" % verify.check_signature(sig))

    dh_grp = 'secp256r1'.encode('utf-8')
    #dh_grp = 'curve25519'.encode('utf-8')
    dh_kdf = 'KDF2(SHA-384)'.encode('utf-8')
    a_dh_priv = private_key('ecdh', dh_grp, r)
    a_dh_pub = a_dh_priv.get_public_key()

    b_dh_priv = private_key('ecdh', dh_grp, r)
    b_dh_pub = b_dh_priv.get_public_key()

    a_dh = pk_op_key_agreement(a_dh_priv, dh_kdf)
    b_dh = pk_op_key_agreement(b_dh_priv, dh_kdf)

    print("ecdh pubs:\n  %s\n  %s\n" %
          (hexlify(a_dh.public_value()).decode('utf-8'),
           hexlify(b_dh.public_value()).decode('utf-8')))

    a_key = a_dh.agree(b_dh.public_value(), 20, 'salt'.encode('utf-8'))
    b_key = b_dh.agree(a_dh.public_value(), 20, 'salt'.encode('utf-8'))

    print("ecdh shared:\n  %s\n  %s\n" %
          (hexlify(a_key).decode('utf-8'), hexlify(b_key).decode('utf-8')))


    #f = open('key.ber','wb')
    #f.write(blob)
    #f.close()


def main(args = None):
    if args is None:
        args = sys.argv
    test()

if __name__ == '__main__':
    sys.exit(main())
