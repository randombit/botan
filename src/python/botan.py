#!/usr/bin/env python

"""Python wrapper of the botan crypto library
http://botan.randombit.net

(C) 2015 Jack Lloyd
(C) 2015 Uri  Blumenthal (extensions and patches)

Botan is released under the Simplified BSD License (see license.txt)

This module uses the ctypes module and is usable by programs running
under at least CPython 2.7, CPython 3.4 and 3.5, or PyPy.

It uses botan's ffi module, which exposes a C API. Right now the C API
is versioned but as it is still in evolution, no provisions are made
for handling more than a single API version in this module. So this
module should be used only with the library version it accompanied.
"""

import sys
from ctypes import *
from binascii import hexlify, unhexlify, b2a_base64
from datetime import datetime
import time

"""
Module initialization
"""
if sys.platform == 'darwin':
    botan = CDLL('libbotan-1.11.dylib')
else:
    botan = CDLL('libbotan-1.11.so')

expected_api_rev = 20151015
botan_api_rev = botan.botan_ffi_api_version()

if botan_api_rev != expected_api_rev:
    raise Exception("Bad botan API rev got %d expected %d" % (botan_api_rev, expected_api_rev))

# Internal utilities
def _call_fn_returning_vec(guess, fn):

    buf = create_string_buffer(guess)
    buf_len = c_size_t(len(buf))

    rc = fn(buf, byref(buf_len))
    if rc < 0:
        if buf_len.value > len(buf):
            #print("Calling again with %d" % (buf_len.value))
            return _call_fn_returning_vec(buf_len.value, fn)
        else:
            raise Exception("Call failed: %d" % (rc))

    assert buf_len.value <= len(buf)
    return buf.raw[0:buf_len.value]

def _call_fn_returning_string(guess, fn):
    # Assumes that anything called with this is returning plain ASCII strings
    # (base64 data, algorithm names, etc)
    v = _call_fn_returning_vec(guess, fn)
    return v.decode('ascii')[:-1]

def _ctype_str(s):
    assert(type(s) == type(""))
    if sys.version_info[0] < 3:
        return s
    else:
        return s.encode('utf-8')

def _ctype_bits(s):
    # TODO typecheck for bytes in python3?
    if sys.version_info[0] < 3:
        return s
    else:
        if isinstance(s, bytes):
            return s
        elif isinstance(s, str):
            return s.encode('utf-8') # FIXME
        else:
            assert False

def _ctype_bufout(buf):
    if sys.version_info[0] < 3:
        return str(buf.raw)
    else:
        return buf.raw

def hex_encode(buf):
    return hexlify(buf).decode('ascii')

def hex_decode(buf):
    return unhexlify(buf.encode('ascii'))

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
    return botan.botan_version_string().decode('ascii')

"""
RNG
"""
class rng(object):
    # Can also use type "system"
    def __init__(self, rng_type = 'system'):
        botan.botan_rng_init.argtypes = [c_void_p, c_char_p]
        self.rng = c_void_p(0)
        rc = botan.botan_rng_init(byref(self.rng), _ctype_str(rng_type))
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
        return _ctype_bufout(out)

"""
Hash function
"""
class hash_function(object):
    def __init__(self, algo):
        botan.botan_hash_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = c_uint32(0) # always zero in this API version
        self.hash = c_void_p(0)
        rc = botan.botan_hash_init(byref(self.hash), _ctype_str(algo), flags)
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
        botan.botan_hash_update(self.hash, _ctype_bits(x), len(x))

    def final(self):
        botan.botan_hash_final.argtypes = [c_void_p, POINTER(c_char)]
        out = create_string_buffer(self.output_length())
        botan.botan_hash_final(self.hash, out)
        return _ctype_bufout(out)

"""
Message authentication codes
"""
class message_authentication_code(object):
    def __init__(self, algo):
        botan.botan_mac_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = c_uint32(0) # always zero in this API version
        self.mac = c_void_p(0)
        rc = botan.botan_mac_init(byref(self.mac), _ctype_str(algo), flags)
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
        return _ctype_bufout(out)

class cipher(object):
    def __init__(self, algo, encrypt = True):
        botan.botan_cipher_init.argtypes = [c_void_p,c_char_p, c_uint32]
        flags = 0 if encrypt else 1
        self.cipher = c_void_p(0)
        rc = botan.botan_cipher_init(byref(self.cipher), _ctype_str(algo), flags)
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

    def key_length(self):
        kmin = c_size_t(0)
        kmax = c_size_t(0)
        botan.botan_cipher_query_keylen(self.cipher, byref(kmin), byref(kmax))
        return kmin.value, kmax.value

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
        inp_consumed = c_size_t(0)
        out = create_string_buffer(inp_sz.value + (self.tag_length() if final else 0))
        out_sz = c_size_t(len(out))
        out_written = c_size_t(0)
        flags = c_uint32(1 if final else 0)

        botan.botan_cipher_update(self.cipher, flags,
                                  out, out_sz, byref(out_written),
                                  _ctype_bits(inp), inp_sz, byref(inp_consumed))

        # buffering not supported yet
        assert inp_consumed.value == inp_sz.value
        return out.raw[0:out_written.value]

    def update(self, txt):
        return self._update(txt, False)

    def finish(self, txt = None):
        return self._update(txt, True)


"""
Bcrypt
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
    botan.botan_pbkdf(_ctype_str(algo), out_buf, out_len, _ctype_str(password), salt, len(salt), iterations)
    return (salt,iterations,out_buf.raw)

def pbkdf_timed(algo, password, out_len, ms_to_run = 300, salt = rng().get(12)):
    botan.botan_pbkdf_timed.argtypes = [c_char_p, POINTER(c_char), c_size_t, c_char_p,
                                        c_void_p, c_size_t, c_size_t, POINTER(c_size_t)]
    out_buf = create_string_buffer(out_len)
    iterations = c_size_t(0)
    botan.botan_pbkdf_timed(_ctype_str(algo), out_buf, out_len, _ctype_str(password), salt, len(salt), ms_to_run, byref(iterations))
    return (salt,iterations.value,out_buf.raw)

"""
KDF
"""
def kdf(algo, secret, out_len, salt):
    botan.botan_kdf.argtypes = [c_char_p, POINTER(c_char), c_size_t, POINTER(c_char), c_size_t, POINTER(c_char), c_size_t]
    out_buf = create_string_buffer(out_len)
    out_sz = c_size_t(out_len)
    botan.botan_kdf(_ctype_str(algo), out_buf, out_sz, secret, len(secret), salt, len(salt))
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
        return _call_fn_returning_string(32, lambda b,bl: botan.botan_pubkey_algo_name(self.pubkey, b, bl))

    def encoding(self, pem = False):
        botan.botan_pubkey_export.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t), c_uint32]
        flag = 1 if pem else 0
        return _call_fn_returning_vec(0, lambda b,bl: botan.botan_pubkey_export(self.pubkey, b, bl, flag))

    def fingerprint(self, hash = 'SHA-256'):
        botan.botan_pubkey_fingerprint.argtypes = [c_void_p, c_char_p,
                                                   POINTER(c_char), POINTER(c_size_t)]

        n = hash_function(hash).output_length()
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)

        botan.botan_pubkey_fingerprint(self.pubkey, _ctype_str(hash), buf, byref(buf_len))
        return hex_encode(buf[0:buf_len.value])

class private_key(object):
    def __init__(self, alg, param, rng):
        botan.botan_privkey_create_rsa.argtypes = [c_void_p, c_void_p, c_size_t]
        botan.botan_privkey_create_ecdsa.argtypes = [c_void_p, c_void_p, c_char_p]
        botan.botan_privkey_create_ecdh.argtypes = [c_void_p, c_void_p, c_char_p]
        botan.botan_privkey_create_mceliece.argtypes = [c_void_p, c_void_p, c_size_t, c_size_t]

        self.privkey = c_void_p(0)

        if alg == 'rsa':
            botan.botan_privkey_create_rsa(byref(self.privkey), rng.rng, param)
        elif alg == 'ecdsa':
            botan.botan_privkey_create_ecdsa(byref(self.privkey), rng.rng, _ctype_str(param))
        elif alg == 'ecdh':
            botan.botan_privkey_create_ecdh(byref(self.privkey), rng.rng, _ctype_str(param))
        elif alg in ['mce', 'mceliece']:
            botan.botan_privkey_create_mceliece(byref(self.privkey), rng.rng, param[0], param[1])
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
        print("Padding is ", padding)
        botan.botan_pk_op_encrypt_create(byref(self.op), key.pubkey, _ctype_str(padding), flags)
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
        #if sys.version_info[0] > 2:
        #    msg = cast(msg, c_char_p)
        #    ll = c_size_t(ll)
        botan.botan_pk_op_encrypt(self.op, rng.rng, outbuf, byref(outbuf_sz), msg, ll)
        #print("encrypt: outbuf_sz.value=%d" % outbuf_sz.value)
        return outbuf.raw[0:outbuf_sz.value]


class pk_op_decrypt(object):
    def __init__(self, key, padding):
        botan.botan_pk_op_decrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_decrypt_create(byref(self.op), key.privkey, _ctype_str(padding), flags)
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
        botan.botan_pk_op_decrypt(self.op, outbuf, byref(outbuf_sz), _ctype_bits(msg), ll)
        return outbuf.raw[0:outbuf_sz.value]

class pk_op_sign(object):
    def __init__(self, key, padding):
        botan.botan_pk_op_sign_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_sign_create(byref(self.op), key.privkey, _ctype_str(padding), flags)
        if not self.op:
            raise Exception("No pk op for you")

    def __del__(self):
        botan.botan_pk_op_sign_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_sign_destroy(self.op)

    def update(self, msg):
        botan.botan_pk_op_sign_update.argtypes = [c_void_p,  POINTER(c_char), c_size_t]
        botan.botan_pk_op_sign_update(self.op, _ctype_str(msg), len(msg))

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
        botan.botan_pk_op_verify_create(byref(self.op), key.pubkey, _ctype_str(padding), flags)
        if not self.op:
            raise Exception("No pk op for you")

    def __del__(self):
        botan.botan_pk_op_verify_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_verify_destroy(self.op)

    def update(self, msg):
        botan.botan_pk_op_verify_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_pk_op_verify_update(self.op, _ctype_bits(msg), len(msg))

    def check_signature(self, signature):
        botan.botan_pk_op_verify_finish.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        rc = botan.botan_pk_op_verify_finish(self.op, _ctype_bits(signature), len(signature))
        if rc == 0:
            return True
        return False

"""
MCEIES encryption
Must be used with McEliece keys
"""
def mceies_encrypt(mce, rng, aead, pt, ad):
    botan.botan_mceies_encrypt.argtypes = [c_void_p, c_void_p, c_char_p, POINTER(c_char), c_size_t,
                                           POINTER(c_char), c_size_t, POINTER(c_char), POINTER(c_size_t)]

    return _call_fn_returning_vec(0, lambda b,bl:
                                  botan.botan_mceies_encrypt(mce.pubkey,
                                                             rng.rng,
                                                             _ctype_str(aead),
                                                             _ctype_bits(pt),
                                                             len(pt),
                                                             _ctype_bits(ad),
                                                             len(ad),
                                                             b, bl))

def mceies_decrypt(mce, aead, pt, ad):
    botan.botan_mceies_decrypt.argtypes = [c_void_p, c_char_p, POINTER(c_char), c_size_t,
                                           POINTER(c_char), c_size_t, POINTER(c_char), POINTER(c_size_t)]

    #msg = cast(msg, c_char_p)
    #ll = c_size_t(ll)

    return _call_fn_returning_vec(0, lambda b,bl:
                                  botan.botan_mceies_decrypt(mce.privkey,
                                                             _ctype_str(aead),
                                                             _ctype_bits(pt),
                                                             len(pt),
                                                             _ctype_bits(ad),
                                                             len(ad),
                                                             b, bl))

class pk_op_key_agreement(object):
    def __init__(self, key, kdf):
        botan.botan_pk_op_key_agreement_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        botan.botan_pk_op_key_agreement_export_public.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_key_agreement_create(byref(self.op), key.privkey, kdf, flags)
        if not self.op:
            raise Exception("No key agreement for you")

        self.m_public_value = _call_fn_returning_vec(0, lambda b, bl: botan.botan_pk_op_key_agreement_export_public(key.privkey, b, bl))

    def __del__(self):
        botan.botan_pk_op_key_agreement_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_key_agreement_destroy(self.op)

    def public_value(self):
        return self.m_public_value

    def agree(self, other, key_len, salt):
        botan.botan_pk_op_key_agreement.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t),
                                                    POINTER(c_char), c_size_t, POINTER(c_char), c_size_t]

        return _call_fn_returning_vec(key_len,
                                      lambda b,bl: botan.botan_pk_op_key_agreement(self.op, b, bl,
                                                                                   other, len(other),
                                                                                   salt, len(salt)))
"""
X.509 certificates
"""
class x509_cert(object):
    def __init__(self, filename=None, buf=None):
        if filename is None and buf is None:
            raise ArgumentError("No filename or buf given")
        if filename is not None and buf is not None:
            raise ArgumentError("Both filename and buf given")
        elif filename is not None:
            botan.botan_x509_cert_load_file.argtypes = [POINTER(c_void_p), c_char_p]
            self.x509_cert = c_void_p(0)
            botan.botan_x509_cert_load_file(byref(self.x509_cert), _ctype_str(filename))
        elif buf is not None:
            botan.botan_x509_cert_load.argtypes = [POINTER(c_void_p), POINTER(c_char), c_size_t]
            self.x509_cert = c_void_p(0)
            botan.botan_x509_cert_load(byref(self.x509_cert), _ctype_bits(buf), len(buf))

    def __del__(self):
        botan.botan_x509_cert_destroy.argtypes = [c_void_p]
        botan.botan_x509_cert_destroy(self.x509_cert)

    def time_starts(self):
        botan.botan_x509_cert_get_time_starts.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        starts = _call_fn_returning_string(16, lambda b,bl: botan.botan_x509_cert_get_time_starts(self.x509_cert, b, bl))
        if len(starts) == 13:
            # UTC time
            struct_time = time.strptime(starts, "%y%m%d%H%M%SZ")
        elif len(starts) == 15:
            # Generalized time
            struct_time = time.strptime(starts, "%Y%m%d%H%M%SZ")
        else:
            raise Exception("Wrong date/time format")

        return datetime.fromtimestamp(time.mktime(struct_time))

    def time_expires(self):
        botan.botan_x509_cert_get_time_expires.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        expires = _call_fn_returning_string(16, lambda b,bl: botan.botan_x509_cert_get_time_expires(self.x509_cert, b, bl))
        if len(expires) == 13:
            # UTC time
            struct_time = time.strptime(expires, "%y%m%d%H%M%SZ")
        elif len(expires) == 15:
            # Generalized time
            struct_time = time.strptime(expires, "%Y%m%d%H%M%SZ")
        else:
            raise Exception("Wrong date/time format")
        return datetime.fromtimestamp(time.mktime(struct_time))

    def to_string(self):
        botan.botan_x509_cert_to_string.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_string(0, lambda b,bl: botan.botan_x509_cert_to_string(self.x509_cert, b, bl))

    def fingerprint(self, hash_algo = 'SHA-256'):
        botan.botan_x509_cert_get_fingerprint.argtypes = [c_void_p, c_char_p,
                                                          POINTER(c_char), POINTER(c_size_t)]

        n = hash_function(hash_algo).output_length() * 3
        return _call_fn_returning_string(n, lambda b,bl: botan.botan_x509_cert_get_fingerprint(self.x509_cert, _ctype_str(hash_algo), b, bl))

    def serial_number(self):
        botan.botan_x509_cert_get_serial_number.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_vec(0, lambda b,bl: botan.botan_x509_cert_get_serial_number(self.x509_cert, b, bl))

    def authority_key_id(self):
        botan.botan_x509_cert_get_authority_key_id.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_vec(0, lambda b,bl: botan.botan_x509_cert_get_authority_key_id(self.x509_cert, b, bl))

    def subject_key_id(self):
        botan.botan_x509_cert_get_subject_key_id.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_vec(0, lambda b,bl: botan.botan_x509_cert_get_subject_key_id(self.x509_cert, b, bl))

    def subject_public_key_bits(self):
        botan.botan_x509_cert_get_public_key_bits.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_vec(0, lambda b,bl: botan.botan_x509_cert_get_public_key_bits(self.x509_cert, b, bl))

    def subject_public_key(self):
        botan.botan_x509_cert_get_public_key.argtypes = [c_void_p, c_void_p]
        pub = c_void_p(0)
        botan.botan_x509_cert_get_public_key(self.x509_cert, byref(pub))

        return public_key(pub)

    def subject_dn(self, key, index):
        botan.botan_x509_cert_get_subject_dn.argtypes = [c_void_p, c_char_p, c_size_t, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_string(0, lambda b,bl: botan.botan_x509_cert_get_subject_dn(self.x509_cert, _ctype_str(key), index, b, bl))


"""
Tests and examples
"""
def test():

    def test_version():

        print("\n%s" % version_string())
        print("v%d.%d.%d\n" % (version_major(), version_minor(), version_patch()))
        print("\nPython %s\n" % sys.version.replace('\n', ' '))

    def test_kdf():
        print("KDF2(SHA-1)   %s" %
              hex_encode(kdf('KDF2(SHA-1)', hex_decode('701F3480DFE95F57941F804B1B2413EF'), 7,
                             hex_decode('55A4E9DD5F4CA2EF82'))))

    def test_pbkdf():
        print("PBKDF2(SHA-1) %s" %
              hex_encode(pbkdf('PBKDF2(SHA-1)', '', 32, 10000, hex_decode('0001020304050607'))[2]))
        print("good output   %s\n" %
              '59B2B1143B4CB1059EC58D9722FB1C72471E0D85C6F7543BA5228526375B0127')

        (salt,iterations,psk) = pbkdf_timed('PBKDF2(SHA-256)', 'xyz', 32, 200)

        print("PBKDF2(SHA-256) x=timed, y=iterated; salt = %s (len=%d)  #iterations = %d\n" %
              (hex_encode(salt), len(salt), iterations))

        print('x %s' % hex_encode(psk))
        print('y %s\n' % (hex_encode(pbkdf('PBKDF2(SHA-256)', 'xyz', 32, iterations, salt)[2])))

    def test_hmac():

        hmac = message_authentication_code('HMAC(SHA-256)')
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
        user_rng = rng("user")

        print("rng output:\n\t%s\n\t%s\n\t%s\n" %
              (hex_encode(user_rng.get(42)),
               hex_encode(user_rng.get(13)),
               hex_encode(user_rng.get(9))))

    def test_hash():
        md5 = hash_function('MD5')
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
            enc = cipher(mode, encrypt=True)

            (kmin,kmax) = enc.key_length()
            print("%s: default nonce=%d update_size=%d key_min=%d key_max=%d" %
                  (mode, enc.default_nonce_length(), enc.update_granularity(), kmin, kmax))
            iv = rng().get(enc.default_nonce_length())
            key = rng().get(kmax)
            pt = rng().get(21)

            print("  plaintext  %s (%d)"   % (hex_encode(pt), len(pt)))

            enc.set_key(key)
            enc.start(iv)
            assert len(enc.update('')) == 0
            ct = enc.finish(pt)
            print("  ciphertext %s (%d)" % (hex_encode(ct), len(ct)))

            dec = cipher(mode, encrypt=False)
            dec.set_key(key)
            dec.start(iv)
            decrypted = dec.finish(ct)

            print("  decrypted  %s (%d)\n" % (hex_encode(decrypted), len(decrypted)))


    def test_mceliece():
        mce_priv = private_key('mce', [2960,57], rng())
        mce_pub = mce_priv.get_public_key()

        mce_plaintext = 'mce plaintext'
        mce_ad = 'mce AD'
        mce_ciphertext = mceies_encrypt(mce_pub, rng(), 'ChaCha20Poly1305', mce_plaintext, mce_ad)

        print("mceies len(pt)=%d  len(ct)=%d" % (len(mce_plaintext), len(mce_ciphertext)))

        mce_decrypt = mceies_decrypt(mce_priv, 'ChaCha20Poly1305', mce_ciphertext, mce_ad)
        print("  mceies plaintext  \'%s\' (%d)" % (mce_plaintext, len(mce_plaintext)))
        
        # Since mceies_decrypt() returns bytes in Python3, the following line
        # needs .decode('utf-8') to convert mce_decrypt from bytes to a
        # text string (Unicode).
        # You don't need to add .decode() if
        # (a) your expected output is bytes rather than a text string, or
        # (b) you are using Python2 rather than Python3.
        print("  mceies decrypted  \'%s\' (%d)" % (mce_decrypt.decode('utf-8'), len(mce_decrypt)))

        print("mce_pub %s/SHA-1 fingerprint: %s\nEstimated strength %s bits (len %d)\n" %
              (mce_pub.algo_name(), mce_pub.fingerprint("SHA-1"),
               mce_pub.estimated_strength(), len(mce_pub.encoding())
              )
        )

    def test_rsa():
        rsapriv = private_key('rsa', 1536, rng())
        rsapub = rsapriv.get_public_key()

        print("rsapub %s SHA-1 fingerprint: %s estimated strength %d (len %d)" %
              (rsapub.algo_name(), rsapub.fingerprint("SHA-1"),
               rsapub.estimated_strength(), len(rsapub.encoding())
              )
        )

        dec = pk_op_decrypt(rsapriv, "EME1(SHA-256)")
        enc = pk_op_encrypt(rsapub, "EME1(SHA-256)")

        sys_rng = rng()
        symkey = sys_rng.get(32)
        ctext = enc.encrypt(symkey, sys_rng)
        print("ptext   \'%s\' (%d)" % (hex_encode(symkey), len(symkey)))
        print("ctext   \'%s\' (%d)" % (hex_encode(ctext), len(ctext)))
        print("decrypt \'%s\' (%d)\n" % (hex_encode(dec.decrypt(ctext)),
                                         len(dec.decrypt(ctext))))

        signer = pk_op_sign(rsapriv, 'EMSA4(SHA-384)')

        signer.update('messa')
        signer.update('ge')
        sig = signer.finish(rng())

        print("EMSA4(SHA-384) signature: %s" % hex_encode(sig))

        verify = pk_op_verify(rsapub, 'EMSA4(SHA-384)')

        verify.update('mess')
        verify.update('age')
        print("good sig accepted? %s" % verify.check_signature(sig))

        verify.update('mess of things')
        verify.update('age')
        print("bad sig accepted?  %s" % verify.check_signature(sig))

        verify.update('message')
        print("good sig accepted? %s\n" % verify.check_signature(sig))

    def test_dh():
        a_rng = rng('user')
        b_rng = rng('user')

        for dh_grp in ['secp256r1', 'curve25519']:
            dh_kdf = 'KDF2(SHA-384)'.encode('utf-8')
            a_dh_priv = private_key('ecdh', dh_grp, rng())
            a_dh_pub = a_dh_priv.get_public_key()

            b_dh_priv = private_key('ecdh', dh_grp, rng())
            b_dh_pub = b_dh_priv.get_public_key()

            a_dh = pk_op_key_agreement(a_dh_priv, dh_kdf)
            b_dh = pk_op_key_agreement(b_dh_priv, dh_kdf)

            a_salt = a_rng.get(8)
            b_salt = b_rng.get(8)

            print("ecdh %s pubs:\n  %s (salt %s)\n  %s (salt %s)\n" %
                  (dh_grp,
                   hex_encode(a_dh.public_value()),
                   hex_encode(a_salt),
                   hex_encode(b_dh.public_value()),
                   hex_encode(b_salt)))

            a_key = a_dh.agree(b_dh.public_value(), 32, a_salt + b_salt)
            b_key = b_dh.agree(a_dh.public_value(), 32, a_salt + b_salt)

            print("ecdh %s shared:\n  %s\n  %s\n" %
                  (dh_grp, hex_encode(a_key), hex_encode(b_key)))

    def test_certs():
        cert = x509_cert(filename="src/tests/data/ecc/CSCA.CSCA.csca-germany.1.crt")
        print("CSCA (Germany) Certificate\nDetails:")
        print("SHA-1 fingerprint:   %s" % cert.fingerprint("SHA-1"))
        print("Expected:            32:42:1C:C3:EC:54:D7:E9:43:EC:51:F0:19:23:BD:85:1D:F2:1B:B9")

        print("Not before:          %s" % cert.time_starts())
        print("Not after:           %s" % cert.time_expires())

        print("Serial number:       %s" % hex_encode(cert.serial_number()))
        print("Authority Key ID:    %s" % hex_encode(cert.authority_key_id()))
        print("Subject   Key ID:    %s" % hex_encode(cert.subject_key_id()))
        print("Public key bits:\n%s\n" % b2a_base64(cert.subject_public_key_bits()))

        pubkey = cert.subject_public_key()
        print("Public key algo:     %s" % pubkey.algo_name())
        print("Public key strength: %s" % pubkey.estimated_strength() + " bits" )

        dn_fields = ("Name", "Email", "Organization", "Organizational Unit", "Country")
        for field in dn_fields:
            try:
                print("%s: %s" % (field, cert.subject_dn(field, 0)))
            except Exception:
                print("Field: %s not found in certificate" % field)

        print(cert.to_string())

    test_version()
    test_kdf()
    test_pbkdf()
    test_hmac()
    test_rng()
    test_hash()
    test_cipher()
    test_mceliece()
    test_rsa()
    test_dh()
    test_certs()


def main(args = None):
    if args is None:
        args = sys.argv
    test()

if __name__ == '__main__':
    sys.exit(main())
