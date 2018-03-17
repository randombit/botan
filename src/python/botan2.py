#!/usr/bin/env python

"""
Python wrapper of the botan crypto library
https://botan.randombit.net

(C) 2015,2017 Jack Lloyd
(C) 2015 Uri  Blumenthal (extensions and patches)

Botan is released under the Simplified BSD License (see license.txt)

This module uses the ctypes module and is usable by programs running
under at least CPython 2.7, CPython 3.4 and 3.5, or PyPy.

It uses botan's ffi module, which exposes a C API. It suppports all
versions of Botan >= 2.0
"""

import sys
from ctypes import CDLL, POINTER, byref, c_void_p, c_size_t, c_uint32, c_int, c_char, c_char_p, create_string_buffer
from binascii import hexlify
from datetime import datetime
import time


#
# Base exception for all exceptions raised from this module
#
class BotanException(Exception):
    pass


#
# Module initialization
#

def load_botan_dll(expected_version):

    possible_dll_names = ['libbotan-2.dylib', 'libbotan-2.so'] + \
                         ['libbotan-2.so.%d' % (v) for v in reversed(range(0, 16))]

    for dll_name in possible_dll_names:
        try:
            dll = CDLL(dll_name)
            dll.botan_ffi_supports_api.argtypes = [c_uint32]
            dll.botan_ffi_supports_api.restype = c_int
            if dll.botan_ffi_supports_api(expected_version) == 0:
                return dll
        except OSError:
            pass

    return None

botan = load_botan_dll(20150515) # pylint: disable=invalid-name

if botan is None:
    raise BotanException("Could not find a usable Botan shared object library")

#
# Internal utilities
#
def _call_fn_returning_vec(guess, fn):

    buf = create_string_buffer(guess)
    buf_len = c_size_t(len(buf))

    rc = fn(buf, byref(buf_len))
    if rc < 0:
        if buf_len.value > len(buf):
            #print("Calling again with %d" % (buf_len.value))
            return _call_fn_returning_vec(buf_len.value, fn)
        else:
            raise BotanException("Call failed: %d" % (rc))

    assert buf_len.value <= len(buf)
    return buf.raw[0:int(buf_len.value)]

def _call_fn_returning_string(guess, fn):
    # Assumes that anything called with this is returning plain ASCII strings
    # (base64 data, algorithm names, etc)
    v = _call_fn_returning_vec(guess, fn)
    return v.decode('ascii')[:-1]

def _ctype_str(s):
    assert isinstance(s, str)
    if sys.version_info[0] < 3:
        return s
    else:
        return s.encode('utf-8')

def _ctype_bits(s):
    if sys.version_info[0] < 3:
        if isinstance(s, str):
            return s
        else:
            raise Exception("Internal error - unexpected type provided to _ctype_bits")
    else:
        if isinstance(s, bytes):
            return s
        elif isinstance(s, str):
            return s.encode('utf-8')
        else:
            raise Exception("Internal error - unexpected type provided to _ctype_bits")

def _ctype_bufout(buf):
    if sys.version_info[0] < 3:
        return str(buf.raw)
    else:
        return buf.raw

def _hex_encode(buf):
    return hexlify(buf).decode('ascii')

#
# Versions
#
def version_major():
    return botan.botan_version_major()

def version_minor():
    return botan.botan_version_minor()

def version_patch():
    return botan.botan_version_patch()

def version_string():
    botan.botan_version_string.restype = c_char_p
    return botan.botan_version_string().decode('ascii')

#
# RNG
#
class rng(object): # pylint: disable=invalid-name
    # Can also use type "system"
    def __init__(self, rng_type='system'):
        botan.botan_rng_init.argtypes = [c_void_p, c_char_p]
        self.rng = c_void_p(0)
        rc = botan.botan_rng_init(byref(self.rng), _ctype_str(rng_type))
        if rc != 0 or self.rng is None:
            raise BotanException("No rng " + rng_type + " available")

    def __del__(self):
        botan.botan_rng_destroy.argtypes = [c_void_p]
        botan.botan_rng_destroy(self.rng)

    def reseed(self, bits=256):
        botan.botan_rng_reseed.argtypes = [c_void_p, c_size_t]
        botan.botan_rng_reseed(self.rng, bits)

    def get(self, length):
        botan.botan_rng_get.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        out = create_string_buffer(length)
        l = c_size_t(length)
        rc = botan.botan_rng_get(self.rng, out, l)
        if rc == 0:
            return _ctype_bufout(out)
        else:
            return None

#
# Hash function
#
class hash_function(object): # pylint: disable=invalid-name
    def __init__(self, algo):
        botan.botan_hash_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = c_uint32(0) # always zero in this API version
        self.hash = c_void_p(0)
        rc = botan.botan_hash_init(byref(self.hash), _ctype_str(algo), flags)
        if rc != 0 or self.hash is None:
            raise BotanException("No hash " + algo + " for you!")

    def __del__(self):
        botan.botan_hash_destroy.argtypes = [c_void_p]
        botan.botan_hash_destroy(self.hash)

    def clear(self):
        botan.botan_hash_clear.argtypes = [c_void_p]
        return botan.botan_hash_clear(self.hash)

    def output_length(self):
        botan.botan_hash_output_length.argtypes = [c_void_p, POINTER(c_size_t)]
        l = c_size_t(0)
        rc = botan.botan_hash_output_length(self.hash, byref(l))
        if rc == 0:
            return l.value
        raise BotanException("botan_hash_output_length failed")

    def update(self, x):
        botan.botan_hash_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_hash_update(self.hash, _ctype_bits(x), len(x))

    def final(self):
        botan.botan_hash_final.argtypes = [c_void_p, POINTER(c_char)]
        out = create_string_buffer(self.output_length())
        botan.botan_hash_final(self.hash, out)
        return _ctype_bufout(out)

#
# Message authentication codes
#
class message_authentication_code(object): # pylint: disable=invalid-name
    def __init__(self, algo):
        botan.botan_mac_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = c_uint32(0) # always zero in this API version
        self.mac = c_void_p(0)
        rc = botan.botan_mac_init(byref(self.mac), _ctype_str(algo), flags)
        if rc != 0 or self.mac is None:
            raise BotanException("No mac " + algo + " for you!")

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
        if rc == 0:
            return l.value
        raise BotanException("botan_mac_output_length failed")

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

class cipher(object): # pylint: disable=invalid-name
    def __init__(self, algo, encrypt=True):
        botan.botan_cipher_init.argtypes = [c_void_p, c_char_p, c_uint32]
        flags = 0 if encrypt else 1
        self.cipher = c_void_p(0)
        rc = botan.botan_cipher_init(byref(self.cipher), _ctype_str(algo), flags)
        if rc != 0 or self.cipher is None:
            raise BotanException("No cipher " + algo + " for you!")

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
            raise BotanException('Error calling valid_nonce_length')
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
        return out.raw[0:int(out_written.value)]

    def update(self, txt):
        return self._update(txt, False)

    def finish(self, txt=None):
        return self._update(txt, True)


def bcrypt(passwd, rng_instance, work_factor=10):
    """
    Bcrypt password hashing
    """
    botan.botan_bcrypt_generate.argtypes = [POINTER(c_char), POINTER(c_size_t),
                                            c_char_p, c_void_p, c_size_t, c_uint32]
    out_len = c_size_t(64)
    out = create_string_buffer(out_len.value)
    flags = c_uint32(0)
    rc = botan.botan_bcrypt_generate(out, byref(out_len), _ctype_str(passwd),
                                     rng_instance.rng, c_size_t(work_factor), flags)
    if rc != 0:
        raise BotanException('botan bcrypt failed, error %s' % (rc))
    b = out.raw[0:int(out_len.value)-1]
    if b[-1] == '\x00':
        b = b[:-1]
    return b

def check_bcrypt(passwd, passwd_hash):
    rc = botan.botan_bcrypt_is_valid(_ctype_str(passwd), passwd_hash)
    return rc == 0

#
# PBKDF
#
def pbkdf(algo, password, out_len, iterations=10000, salt=rng().get(12)):
    botan.botan_pbkdf.argtypes = [c_char_p, POINTER(c_char), c_size_t, c_char_p, c_void_p, c_size_t, c_size_t]
    out_buf = create_string_buffer(out_len)
    botan.botan_pbkdf(_ctype_str(algo), out_buf, out_len, _ctype_str(password), salt, len(salt), iterations)
    return (salt, iterations, out_buf.raw)

def pbkdf_timed(algo, password, out_len, ms_to_run=300, salt=rng().get(12)):
    botan.botan_pbkdf_timed.argtypes = [c_char_p, POINTER(c_char), c_size_t, c_char_p,
                                        c_void_p, c_size_t, c_size_t, POINTER(c_size_t)]
    out_buf = create_string_buffer(out_len)
    iterations = c_size_t(0)
    botan.botan_pbkdf_timed(
        _ctype_str(algo), out_buf, out_len, _ctype_str(password),
        salt, len(salt), ms_to_run, byref(iterations))
    return (salt, iterations.value, out_buf.raw)

#
# KDF
#
def kdf(algo, secret, out_len, salt, label):
    botan.botan_kdf.argtypes = [c_char_p, POINTER(c_char), c_size_t, POINTER(c_char), c_size_t,
                                POINTER(c_char), c_size_t, POINTER(c_char), c_size_t]
    out_buf = create_string_buffer(out_len)
    out_sz = c_size_t(out_len)
    botan.botan_kdf(_ctype_str(algo), out_buf, out_sz, secret, len(secret),
                    salt, len(salt), label, len(label))
    return out_buf.raw[0:int(out_sz.value)]

#
# Public and private keys
#
class public_key(object): # pylint: disable=invalid-name
    def __init__(self, obj=c_void_p(0)):
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
        return _call_fn_returning_string(32, lambda b, bl: botan.botan_pubkey_algo_name(self.pubkey, b, bl))

    def encoding(self, pem=False):
        botan.botan_pubkey_export.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t), c_uint32]
        flag = 1 if pem else 0
        return _call_fn_returning_vec(0, lambda b, bl: botan.botan_pubkey_export(self.pubkey, b, bl, flag))

    def fingerprint(self, hash_algorithm='SHA-256'):
        botan.botan_pubkey_fingerprint.argtypes = [c_void_p, c_char_p,
                                                   POINTER(c_char), POINTER(c_size_t)]

        n = hash_function(hash_algorithm).output_length()
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)

        botan.botan_pubkey_fingerprint(self.pubkey, _ctype_str(hash_algorithm), buf, byref(buf_len))
        return _hex_encode(buf[0:int(buf_len.value)])

class private_key(object): # pylint: disable=invalid-name
    def __init__(self, alg, param, rng_instance):
        botan.botan_privkey_create_rsa.argtypes = [c_void_p, c_void_p, c_size_t]
        botan.botan_privkey_create_ecdsa.argtypes = [c_void_p, c_void_p, c_char_p]
        botan.botan_privkey_create_ecdh.argtypes = [c_void_p, c_void_p, c_char_p]
        botan.botan_privkey_create_mceliece.argtypes = [c_void_p, c_void_p, c_size_t, c_size_t]

        self.privkey = c_void_p(0)

        if alg == 'rsa':
            botan.botan_privkey_create_rsa(byref(self.privkey), rng_instance.rng, param)
        elif alg == 'ecdsa':
            botan.botan_privkey_create_ecdsa(byref(self.privkey), rng_instance.rng, _ctype_str(param))
        elif alg == 'ecdh':
            botan.botan_privkey_create_ecdh(byref(self.privkey), rng_instance.rng, _ctype_str(param))
        elif alg in ['mce', 'mceliece']:
            botan.botan_privkey_create_mceliece(byref(self.privkey), rng_instance.rng, param[0], param[1])
        else:
            raise BotanException('Unknown public key algo ' + alg)

        if self.privkey is None:
            raise BotanException('Error creating ' + alg + ' key')

    def __del__(self):
        botan.botan_privkey_destroy.argtypes = [c_void_p]
        botan.botan_privkey_destroy(self.privkey)

    def get_public_key(self):
        botan.botan_privkey_export_pubkey.argtypes = [c_void_p, c_void_p]

        pub = c_void_p(0)
        botan.botan_privkey_export_pubkey(byref(pub), self.privkey)
        return public_key(pub)

    def export(self):
        botan.botan_privkey_export.argtypes = [c_void_p, POINTER(c_char), c_void_p]

        n = 4096
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)

        rc = botan.botan_privkey_export(self.privkey, buf, byref(buf_len))
        if rc != 0:
            buf = create_string_buffer(buf_len.value)
            botan.botan_privkey_export(self.privkey, buf, byref(buf_len))
        return buf[0:int(buf_len.value)]

class pk_op_encrypt(object): # pylint: disable=invalid-name
    def __init__(self, key, padding):
        botan.botan_pk_op_encrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        print("Padding is ", padding)
        botan.botan_pk_op_encrypt_create(byref(self.op), key.pubkey, _ctype_str(padding), flags)
        if not self.op:
            raise BotanException("No pk op for you")

    def __del__(self):
        botan.botan_pk_op_encrypt_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_encrypt_destroy(self.op)

    def encrypt(self, msg, rng_instance):
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
        botan.botan_pk_op_encrypt(self.op, rng_instance.rng, outbuf, byref(outbuf_sz), msg, ll)
        #print("encrypt: outbuf_sz.value=%d" % outbuf_sz.value)
        return outbuf.raw[0:int(outbuf_sz.value)]


class pk_op_decrypt(object): # pylint: disable=invalid-name
    def __init__(self, key, padding):
        botan.botan_pk_op_decrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_decrypt_create(byref(self.op), key.privkey, _ctype_str(padding), flags)
        if not self.op:
            raise BotanException("No pk op for you")

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
        return outbuf.raw[0:int(outbuf_sz.value)]

class pk_op_sign(object): # pylint: disable=invalid-name
    def __init__(self, key, padding):
        botan.botan_pk_op_sign_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_sign_create(byref(self.op), key.privkey, _ctype_str(padding), flags)
        if not self.op:
            raise BotanException("No pk op for you")

    def __del__(self):
        botan.botan_pk_op_sign_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_sign_destroy(self.op)

    def update(self, msg):
        botan.botan_pk_op_sign_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
        botan.botan_pk_op_sign_update(self.op, _ctype_str(msg), len(msg))

    def finish(self, rng_instance):
        botan.botan_pk_op_sign_finish.argtypes = [c_void_p, c_void_p, POINTER(c_char), POINTER(c_size_t)]
        outbuf_sz = c_size_t(4096) #?!?!
        outbuf = create_string_buffer(outbuf_sz.value)
        botan.botan_pk_op_sign_finish(self.op, rng_instance.rng, outbuf, byref(outbuf_sz))
        return outbuf.raw[0:int(outbuf_sz.value)]

class pk_op_verify(object): # pylint: disable=invalid-name
    def __init__(self, key, padding):
        botan.botan_pk_op_verify_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_verify_create(byref(self.op), key.pubkey, _ctype_str(padding), flags)
        if not self.op:
            raise BotanException("No pk op for you")

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


#
# MCEIES encryption
# Must be used with McEliece keys
#
def mceies_encrypt(mce, rng_instance, aead, pt, ad):
    botan.botan_mceies_encrypt.argtypes = [c_void_p, c_void_p, c_char_p, POINTER(c_char), c_size_t,
                                           POINTER(c_char), c_size_t, POINTER(c_char), POINTER(c_size_t)]

    return _call_fn_returning_vec(0, lambda b, bl:
                                  botan.botan_mceies_encrypt(mce.pubkey,
                                                             rng_instance.rng,
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

    return _call_fn_returning_vec(0, lambda b, bl:
                                  botan.botan_mceies_decrypt(mce.privkey,
                                                             _ctype_str(aead),
                                                             _ctype_bits(pt),
                                                             len(pt),
                                                             _ctype_bits(ad),
                                                             len(ad),
                                                             b, bl))

class pk_op_key_agreement(object): # pylint: disable=invalid-name
    def __init__(self, key, kdf_name):
        botan.botan_pk_op_key_agreement_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
        botan.botan_pk_op_key_agreement_export_public.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        self.op = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_key_agreement_create(byref(self.op), key.privkey, kdf_name, flags)
        if not self.op:
            raise BotanException("No key agreement for you")

        self.m_public_value = _call_fn_returning_vec(
            0, lambda b, bl: botan.botan_pk_op_key_agreement_export_public(key.privkey, b, bl))

    def __del__(self):
        botan.botan_pk_op_key_agreement_destroy.argtypes = [c_void_p]
        botan.botan_pk_op_key_agreement_destroy(self.op)

    def public_value(self):
        return self.m_public_value

    def agree(self, other, key_len, salt):
        botan.botan_pk_op_key_agreement.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t),
                                                    POINTER(c_char), c_size_t, POINTER(c_char), c_size_t]

        return _call_fn_returning_vec(key_len, lambda b, bl:
                                      botan.botan_pk_op_key_agreement(self.op, b, bl,
                                                                      other, len(other),
                                                                      salt, len(salt)))

#
# X.509 certificates
#
class x509_cert(object): # pylint: disable=invalid-name
    def __init__(self, filename=None, buf=None):
        if filename is None and buf is None:
            raise BotanException("No filename or buf given")
        if filename is not None and buf is not None:
            raise BotanException("Both filename and buf given")
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
        starts = _call_fn_returning_string(
            16, lambda b, bl: botan.botan_x509_cert_get_time_starts(self.x509_cert, b, bl))
        if len(starts) == 13:
            # UTC time
            struct_time = time.strptime(starts, "%y%m%d%H%M%SZ")
        elif len(starts) == 15:
            # Generalized time
            struct_time = time.strptime(starts, "%Y%m%d%H%M%SZ")
        else:
            raise BotanException("Wrong date/time format")

        return datetime.fromtimestamp(time.mktime(struct_time))

    def time_expires(self):
        botan.botan_x509_cert_get_time_expires.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        expires = _call_fn_returning_string(
            16, lambda b, bl: botan.botan_x509_cert_get_time_expires(self.x509_cert, b, bl))
        if len(expires) == 13:
            # UTC time
            struct_time = time.strptime(expires, "%y%m%d%H%M%SZ")
        elif len(expires) == 15:
            # Generalized time
            struct_time = time.strptime(expires, "%Y%m%d%H%M%SZ")
        else:
            raise BotanException("Wrong date/time format")
        return datetime.fromtimestamp(time.mktime(struct_time))

    def to_string(self):
        botan.botan_x509_cert_to_string.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_string(
            0, lambda b, bl: botan.botan_x509_cert_to_string(self.x509_cert, b, bl))

    def fingerprint(self, hash_algo='SHA-256'):
        botan.botan_x509_cert_get_fingerprint.argtypes = [c_void_p, c_char_p,
                                                          POINTER(c_char), POINTER(c_size_t)]

        n = hash_function(hash_algo).output_length() * 3
        return _call_fn_returning_string(
            n, lambda b, bl: botan.botan_x509_cert_get_fingerprint(self.x509_cert, _ctype_str(hash_algo), b, bl))

    def serial_number(self):
        botan.botan_x509_cert_get_serial_number.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_vec(
            0, lambda b, bl: botan.botan_x509_cert_get_serial_number(self.x509_cert, b, bl))

    def authority_key_id(self):
        botan.botan_x509_cert_get_authority_key_id.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_vec(
            0, lambda b, bl: botan.botan_x509_cert_get_authority_key_id(self.x509_cert, b, bl))

    def subject_key_id(self):
        botan.botan_x509_cert_get_subject_key_id.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_vec(
            0, lambda b, bl: botan.botan_x509_cert_get_subject_key_id(self.x509_cert, b, bl))

    def subject_public_key_bits(self):
        botan.botan_x509_cert_get_public_key_bits.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_vec(
            0, lambda b, bl: botan.botan_x509_cert_get_public_key_bits(self.x509_cert, b, bl))

    def subject_public_key(self):
        botan.botan_x509_cert_get_public_key.argtypes = [c_void_p, c_void_p]
        pub = c_void_p(0)
        botan.botan_x509_cert_get_public_key(self.x509_cert, byref(pub))

        return public_key(pub)

    def subject_dn(self, key, index):
        botan.botan_x509_cert_get_subject_dn.argtypes = [
            c_void_p, c_char_p, c_size_t, POINTER(c_char), POINTER(c_size_t)]
        return _call_fn_returning_string(
            0, lambda b, bl: botan.botan_x509_cert_get_subject_dn(self.x509_cert, _ctype_str(key), index, b, bl))
