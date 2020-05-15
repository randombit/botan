#!/usr/bin/python

"""
Python wrapper of the botan crypto library
https://botan.randombit.net

(C) 2015,2017,2018,2019 Jack Lloyd
(C) 2015 Uri  Blumenthal (extensions and patches)

Botan is released under the Simplified BSD License (see license.txt)

This module uses the ctypes module and is usable by programs running
under at least CPython 2.7, CPython 3.x, and PyPy

It uses botan's ffi module, which exposes a C API. This version of the
module requires FFI API version 20180713, which was introduced in
Botan 2.8

"""

from ctypes import CDLL, POINTER, byref, create_string_buffer, \
    c_void_p, c_size_t, c_uint8, c_uint32, c_uint64, c_int, c_uint, c_char_p

from sys import version_info, platform
from time import strptime, mktime, time as system_time
from binascii import hexlify
from datetime import datetime

BOTAN_FFI_VERSION = 20191214

#
# Base exception for all exceptions raised from this module
#
class BotanException(Exception):

    def __init__(self, message, rc=0):

        self.__rc = rc

        if rc == 0:
            super(BotanException, self).__init__(message)
        else:
            descr = _DLL.botan_error_description(rc).decode('ascii')
            super(BotanException, self).__init__("%s: %d (%s)" % (message, rc, descr))

    def error_code(self):
        return self.__rc

#
# Module initialization
#

def _load_botan_dll(expected_version):

    possible_dll_names = []

    if platform in ['win32', 'cygwin', 'msys']:
        possible_dll_names.append('botan.dll')
    elif platform in ['darwin', 'macos']:
        possible_dll_names.append('libbotan-2.dylib')
    else:
        # assumed to be some Unix/Linux system
        possible_dll_names.append('libbotan-2.so')
        possible_dll_names += ['libbotan-2.so.%d' % (v) for v in reversed(range(13, 20))]

    for dll_name in possible_dll_names:
        try:
            dll = CDLL(dll_name)
            dll.botan_ffi_supports_api.argtypes = [c_uint32]
            dll.botan_ffi_supports_api.restype = c_int
            if dll.botan_ffi_supports_api(expected_version) == 0:
                return dll
        except OSError:
            pass

    raise BotanException("Could not find a usable Botan shared object library")

def _errcheck(rc, fn, _args):
    # This errcheck should only be used for int-returning functions
    assert isinstance(rc, int)

    if rc >= 0 or rc in fn.allowed_errors:
        return rc
    raise BotanException('%s failed' % (fn.__name__), rc)

def _set_prototypes(dll):
    # pylint: disable=too-many-statements,line-too-long
    def ffi_api(fn, args, allowed_errors=None):
        if allowed_errors is None:
            allowed_errors = [-10]
        fn.argtypes = args
        fn.restype = c_int
        fn.errcheck = _errcheck
        fn.allowed_errors = allowed_errors

    dll.botan_version_string.argtypes = []
    dll.botan_version_string.restype = c_char_p

    dll.botan_version_string.argtypes = []
    dll.botan_version_string.restype = c_char_p

    dll.botan_version_major.argtypes = []
    dll.botan_version_major.restype = c_uint32

    dll.botan_version_minor.argtypes = []
    dll.botan_version_minor.restype = c_uint32

    dll.botan_version_patch.argtypes = []
    dll.botan_version_patch.restype = c_uint32

    dll.botan_ffi_api_version.argtypes = []
    dll.botan_ffi_api_version.restype = c_uint32

    dll.botan_error_description.argtypes = [c_int]
    dll.botan_error_description.restype = c_char_p

    # These are generated using src/scripts/ffi_decls.py:
    ffi_api(dll.botan_constant_time_compare, [c_void_p, c_void_p, c_size_t], [-1])
    ffi_api(dll.botan_scrub_mem, [c_void_p, c_size_t])

    ffi_api(dll.botan_hex_encode, [c_char_p, c_size_t, c_char_p, c_uint32])
    ffi_api(dll.botan_hex_decode, [c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])

    ffi_api(dll.botan_base64_encode, [c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_base64_decode, [c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])

    #  RNG
    ffi_api(dll.botan_rng_init, [c_void_p, c_char_p])
    ffi_api(dll.botan_rng_get, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_rng_reseed, [c_void_p, c_size_t])
    ffi_api(dll.botan_rng_reseed_from_rng, [c_void_p, c_void_p, c_size_t])
    ffi_api(dll.botan_rng_add_entropy, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_rng_destroy, [c_void_p])

    #  HASH
    ffi_api(dll.botan_hash_init, [c_void_p, c_char_p, c_uint32])
    ffi_api(dll.botan_hash_copy_state, [c_void_p, c_void_p])
    ffi_api(dll.botan_hash_output_length, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_hash_block_size, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_hash_update, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_hash_final, [c_void_p, c_char_p])
    ffi_api(dll.botan_hash_clear, [c_void_p])
    ffi_api(dll.botan_hash_destroy, [c_void_p])
    ffi_api(dll.botan_hash_name, [c_void_p, c_char_p, POINTER(c_size_t)])

    #  MAC
    ffi_api(dll.botan_mac_init, [c_void_p, c_char_p, c_uint32])
    ffi_api(dll.botan_mac_output_length, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_mac_set_key, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_mac_update, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_mac_final, [c_void_p, c_char_p])
    ffi_api(dll.botan_mac_clear, [c_void_p])
    ffi_api(dll.botan_mac_name, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_mac_get_keyspec, [c_void_p, POINTER(c_size_t), POINTER(c_size_t), POINTER(c_size_t)])
    ffi_api(dll.botan_mac_destroy, [c_void_p])

    #  CIPHER
    ffi_api(dll.botan_cipher_init, [c_void_p, c_char_p, c_uint32])
    ffi_api(dll.botan_cipher_name, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_output_length, [c_void_p, c_size_t, POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_valid_nonce_length, [c_void_p, c_size_t])
    ffi_api(dll.botan_cipher_get_tag_length, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_get_default_nonce_length, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_get_update_granularity, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_query_keylen, [c_void_p, POINTER(c_size_t), POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_get_keyspec, [c_void_p, POINTER(c_size_t), POINTER(c_size_t), POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_set_key, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_cipher_reset, [c_void_p])
    ffi_api(dll.botan_cipher_set_associated_data, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_cipher_start, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_cipher_update,
            [c_void_p, c_uint32, c_char_p, c_size_t, POINTER(c_size_t), c_char_p, c_size_t, POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_clear, [c_void_p])
    ffi_api(dll.botan_cipher_destroy, [c_void_p])

    ffi_api(dll.botan_pbkdf,
            [c_char_p, c_char_p, c_size_t, c_char_p, c_char_p, c_size_t, c_size_t])
    ffi_api(dll.botan_pbkdf_timed,
            [c_char_p, c_char_p, c_size_t, c_char_p, c_char_p, c_size_t, c_size_t, POINTER(c_size_t)])

    ffi_api(dll.botan_pwdhash,
            [c_char_p, c_size_t, c_size_t, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t])
    ffi_api(dll.botan_pwdhash_timed,
            [c_char_p, c_uint32, POINTER(c_size_t), POINTER(c_size_t), POINTER(c_size_t), c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t])

    ffi_api(dll.botan_scrypt,
            [c_char_p, c_size_t, c_char_p, c_char_p, c_size_t, c_size_t, c_size_t, c_size_t])

    ffi_api(dll.botan_kdf,
            [c_char_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t])

    #  BLOCK
    ffi_api(dll.botan_block_cipher_init, [c_void_p, c_char_p])
    ffi_api(dll.botan_block_cipher_destroy, [c_void_p])
    ffi_api(dll.botan_block_cipher_clear, [c_void_p])
    ffi_api(dll.botan_block_cipher_set_key, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_block_cipher_block_size, [c_void_p])
    ffi_api(dll.botan_block_cipher_encrypt_blocks, [c_void_p, c_char_p, c_char_p, c_size_t])
    ffi_api(dll.botan_block_cipher_decrypt_blocks, [c_void_p, c_char_p, c_char_p, c_size_t])
    ffi_api(dll.botan_block_cipher_name, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_block_cipher_get_keyspec, [c_void_p, POINTER(c_size_t), POINTER(c_size_t), POINTER(c_size_t)])

    #  MP
    ffi_api(dll.botan_mp_init, [c_void_p])
    ffi_api(dll.botan_mp_destroy, [c_void_p])
    ffi_api(dll.botan_mp_to_hex, [c_void_p, c_char_p])
    ffi_api(dll.botan_mp_to_str, [c_void_p, c_uint8, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_mp_clear, [c_void_p])
    ffi_api(dll.botan_mp_set_from_int, [c_void_p, c_int])
    ffi_api(dll.botan_mp_set_from_mp, [c_void_p, c_void_p])
    ffi_api(dll.botan_mp_set_from_str, [c_void_p, c_char_p])
    ffi_api(dll.botan_mp_set_from_radix_str, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_mp_num_bits, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_mp_num_bytes, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_mp_to_bin, [c_void_p, c_char_p])
    ffi_api(dll.botan_mp_from_bin, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_mp_to_uint32, [c_void_p, POINTER(c_uint32)])
    ffi_api(dll.botan_mp_is_positive, [c_void_p])
    ffi_api(dll.botan_mp_is_negative, [c_void_p])
    ffi_api(dll.botan_mp_flip_sign, [c_void_p])
    ffi_api(dll.botan_mp_is_zero, [c_void_p])
    ffi_api(dll.botan_mp_is_odd, [c_void_p])
    ffi_api(dll.botan_mp_is_even, [c_void_p])
    ffi_api(dll.botan_mp_add_u32, [c_void_p, c_void_p, c_uint32])
    ffi_api(dll.botan_mp_sub_u32, [c_void_p, c_void_p, c_uint32])
    ffi_api(dll.botan_mp_add, [c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_sub, [c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_mul, [c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_div, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_mod_mul, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_equal, [c_void_p, c_void_p])
    ffi_api(dll.botan_mp_cmp, [POINTER(c_int), c_void_p, c_void_p])
    ffi_api(dll.botan_mp_swap, [c_void_p, c_void_p])
    ffi_api(dll.botan_mp_powmod, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_lshift, [c_void_p, c_void_p, c_size_t])
    ffi_api(dll.botan_mp_rshift, [c_void_p, c_void_p, c_size_t])
    ffi_api(dll.botan_mp_mod_inverse, [c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_rand_bits, [c_void_p, c_void_p, c_size_t])
    ffi_api(dll.botan_mp_rand_range, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_gcd, [c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_mp_is_prime, [c_void_p, c_void_p, c_size_t])
    ffi_api(dll.botan_mp_get_bit, [c_void_p, c_size_t])
    ffi_api(dll.botan_mp_set_bit, [c_void_p, c_size_t])
    ffi_api(dll.botan_mp_clear_bit, [c_void_p, c_size_t])

    ffi_api(dll.botan_bcrypt_generate,
            [c_char_p, POINTER(c_size_t), c_char_p, c_void_p, c_size_t, c_uint32])
    ffi_api(dll.botan_bcrypt_is_valid, [c_char_p, c_char_p])

    #  PUBKEY
    ffi_api(dll.botan_privkey_create, [c_void_p, c_char_p, c_char_p, c_void_p])
    ffi_api(dll.botan_privkey_check_key, [c_void_p, c_void_p, c_uint32], [-1])
    ffi_api(dll.botan_privkey_create_rsa, [c_void_p, c_void_p, c_size_t])
    ffi_api(dll.botan_privkey_create_ecdsa, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_create_ecdh, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_create_mceliece, [c_void_p, c_void_p, c_size_t, c_size_t])
    ffi_api(dll.botan_privkey_create_dh, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_create_dsa, [c_void_p, c_void_p, c_size_t, c_size_t])
    ffi_api(dll.botan_privkey_create_elgamal, [c_void_p, c_void_p, c_size_t, c_size_t])
    ffi_api(dll.botan_privkey_load,
            [c_void_p, c_void_p, c_char_p, c_size_t, c_char_p])
    ffi_api(dll.botan_privkey_destroy, [c_void_p])
    ffi_api(dll.botan_privkey_export, [c_void_p, c_char_p, POINTER(c_size_t), c_uint32])
    ffi_api(dll.botan_privkey_algo_name, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_privkey_export_encrypted,
            [c_void_p, c_char_p, POINTER(c_size_t), c_void_p, c_char_p, c_char_p, c_uint32])
    ffi_api(dll.botan_privkey_export_encrypted_pbkdf_msec,
            [c_void_p, c_char_p, POINTER(c_size_t), c_void_p, c_char_p, c_uint32, POINTER(c_size_t), c_char_p, c_char_p, c_uint32])
    ffi_api(dll.botan_privkey_export_encrypted_pbkdf_iter,
            [c_void_p, c_char_p, POINTER(c_size_t), c_void_p, c_char_p, c_size_t, c_char_p, c_char_p, c_uint32])
    ffi_api(dll.botan_privkey_export_pubkey, [c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_load, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_pubkey_export, [c_void_p, c_char_p, POINTER(c_size_t), c_uint32])
    ffi_api(dll.botan_pubkey_algo_name, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pubkey_check_key, [c_void_p, c_void_p, c_uint32], [-1])
    ffi_api(dll.botan_pubkey_estimated_strength, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pubkey_fingerprint, [c_void_p, c_char_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pubkey_destroy, [c_void_p])
    ffi_api(dll.botan_pubkey_get_field, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_get_field, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_rsa, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_load_rsa_pkcs1, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_privkey_rsa_get_p, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_rsa_get_q, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_rsa_get_d, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_rsa_get_n, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_rsa_get_e, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_rsa_get_privkey, [c_void_p, c_char_p, POINTER(c_size_t), c_uint32])
    ffi_api(dll.botan_pubkey_load_rsa, [c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_rsa_get_e, [c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_rsa_get_n, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_load_dsa,
            [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_load_dsa,
            [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_dsa_get_x, [c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_dsa_get_p, [c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_dsa_get_q, [c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_dsa_get_g, [c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_dsa_get_y, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_load_dh, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_load_dh, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_load_elgamal, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_load_elgamal, [c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_load_ed25519, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_ed25519, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_ed25519_get_privkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_ed25519_get_pubkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_x25519, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_x25519, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_x25519_get_privkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_x25519_get_pubkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_ecdsa, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_ecdsa, [c_void_p, c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_ecdh, [c_void_p, c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_ecdh, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_sm2, [c_void_p, c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_sm2, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_sm2_enc, [c_void_p, c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_sm2_enc, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_sm2_compute_za,
            [c_char_p, POINTER(c_size_t), c_char_p, c_char_p, c_void_p])

    #  PK
    ffi_api(dll.botan_pk_op_encrypt_create, [c_void_p, c_void_p, c_char_p, c_uint32])
    ffi_api(dll.botan_pk_op_encrypt_destroy, [c_void_p])
    ffi_api(dll.botan_pk_op_encrypt_output_length, [c_void_p, c_size_t, POINTER(c_size_t)])
    ffi_api(dll.botan_pk_op_encrypt,
            [c_void_p, c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t])
    ffi_api(dll.botan_pk_op_decrypt_create, [c_void_p, c_void_p, c_char_p, c_uint32])
    ffi_api(dll.botan_pk_op_decrypt_destroy, [c_void_p])
    ffi_api(dll.botan_pk_op_decrypt_output_length, [c_void_p, c_size_t, POINTER(c_size_t)])
    ffi_api(dll.botan_pk_op_decrypt,
            [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t])
    ffi_api(dll.botan_pk_op_sign_create, [c_void_p, c_void_p, c_char_p, c_uint32])
    ffi_api(dll.botan_pk_op_sign_destroy, [c_void_p])
    ffi_api(dll.botan_pk_op_sign_output_length, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pk_op_sign_update, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_pk_op_sign_finish, [c_void_p, c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pk_op_verify_create, [c_void_p, c_void_p, c_char_p, c_uint32])
    ffi_api(dll.botan_pk_op_verify_destroy, [c_void_p])
    ffi_api(dll.botan_pk_op_verify_update, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_pk_op_verify_finish, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_pk_op_key_agreement_create, [c_void_p, c_void_p, c_char_p, c_uint32])
    ffi_api(dll.botan_pk_op_key_agreement_destroy, [c_void_p])
    ffi_api(dll.botan_pk_op_key_agreement_export_public, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pk_op_key_agreement_size, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pk_op_key_agreement,
            [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t, c_char_p, c_size_t])

    ffi_api(dll.botan_pkcs_hash_id, [c_char_p, c_char_p, POINTER(c_size_t)])

    ffi_api(dll.botan_mceies_encrypt,
            [c_void_p, c_void_p, c_char_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_mceies_decrypt,
            [c_void_p, c_char_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])

    #  X509
    ffi_api(dll.botan_x509_cert_load, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_x509_cert_load_file, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_destroy, [c_void_p])
    ffi_api(dll.botan_x509_cert_dup, [c_void_p, c_void_p])
    ffi_api(dll.botan_x509_cert_get_time_starts, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_get_time_expires, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_not_before, [c_void_p, POINTER(c_uint64)])
    ffi_api(dll.botan_x509_cert_not_after, [c_void_p, POINTER(c_uint64)])
    ffi_api(dll.botan_x509_cert_get_fingerprint, [c_void_p, c_char_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_get_serial_number, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_get_authority_key_id, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_get_subject_key_id, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_get_public_key_bits, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_get_public_key, [c_void_p, c_void_p])
    ffi_api(dll.botan_x509_cert_get_issuer_dn,
            [c_void_p, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_get_subject_dn,
            [c_void_p, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_to_string, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_allowed_usage, [c_void_p, c_uint])
    ffi_api(dll.botan_x509_cert_hostname_match, [c_void_p, c_char_p], [-1])
    ffi_api(dll.botan_x509_cert_verify,
            [POINTER(c_int), c_void_p, c_void_p, c_size_t, c_void_p, c_size_t, c_char_p, c_size_t, c_char_p, c_uint64])

    dll.botan_x509_cert_validation_status.argtypes = [c_int]
    dll.botan_x509_cert_validation_status.restype = c_char_p

    # X509 CRL
    ffi_api(dll.botan_x509_crl_load, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_x509_crl_load_file, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_crl_destroy, [c_void_p])
    ffi_api(dll.botan_x509_is_revoked, [c_void_p, c_void_p], [-1])
    ffi_api(dll.botan_x509_cert_verify_with_crl,
            [POINTER(c_int), c_void_p, c_void_p, c_size_t, c_void_p, c_size_t, c_void_p, c_size_t, c_char_p, c_size_t, c_char_p, c_uint64])

    ffi_api(dll.botan_key_wrap3394,
            [c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_key_unwrap3394,
            [c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])

    #  HOTP
    ffi_api(dll.botan_hotp_init,
            [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t])
    ffi_api(dll.botan_hotp_destroy, [c_void_p])
    ffi_api(dll.botan_hotp_generate, [c_void_p, POINTER(c_uint32), c_uint64])
    ffi_api(dll.botan_hotp_check,
            [c_void_p, POINTER(c_uint64), c_uint32, c_uint64, c_size_t])

    #  TOTP
    ffi_api(dll.botan_totp_init,
            [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_size_t])
    ffi_api(dll.botan_totp_destroy, [c_void_p])
    ffi_api(dll.botan_totp_generate, [c_void_p, POINTER(c_uint32), c_uint64])
    ffi_api(dll.botan_totp_check, [c_void_p, c_uint32, c_uint64, c_size_t])

    #  FPE
    ffi_api(dll.botan_fpe_fe1_init,
            [c_void_p, c_void_p, c_char_p, c_size_t, c_size_t, c_uint32])
    ffi_api(dll.botan_fpe_destroy, [c_void_p])
    ffi_api(dll.botan_fpe_encrypt, [c_void_p, c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_fpe_decrypt, [c_void_p, c_void_p, c_char_p, c_size_t])

    return dll

#
# Load the DLL and set prototypes on it
#
_DLL = _set_prototypes(_load_botan_dll(BOTAN_FFI_VERSION))

#
# Internal utilities
#
def _call_fn_returning_sz(fn):
    sz = c_size_t(0)
    fn(byref(sz))
    return int(sz.value)

def _call_fn_returning_vec(guess, fn):

    buf = create_string_buffer(guess)
    buf_len = c_size_t(len(buf))

    rc = fn(buf, byref(buf_len))
    if rc == -10 and buf_len.value > len(buf):
        return _call_fn_returning_vec(buf_len.value, fn)

    assert buf_len.value <= len(buf)
    return buf.raw[0:int(buf_len.value)]

def _call_fn_returning_str(guess, fn):
    # Assumes that anything called with this is returning plain ASCII strings
    # (base64 data, algorithm names, etc)
    v = _call_fn_returning_vec(guess, fn)
    return v.decode('ascii')[:-1]

def _ctype_str(s):
    if s is None:
        return None
    assert isinstance(s, str)
    if version_info[0] < 3:
        return s
    else:
        return s.encode('utf-8')

def _ctype_to_str(s):
    if version_info[0] < 3:
        return s.encode('utf-8')
    else:
        return s.decode('utf-8')

def _ctype_bits(s):
    if version_info[0] < 3:
        if isinstance(s, str):
            return s
        elif isinstance(s, unicode): # pylint: disable=undefined-variable
            return s.decode('utf-8')
        else:
            raise Exception("Internal error - unexpected type %s provided to _ctype_bits" % (type(s).__name__))
    else:
        if isinstance(s, bytes):
            return s
        elif isinstance(s, str):
            return s.encode('utf-8')
        else:
            raise Exception("Internal error - unexpected type %s provided to _ctype_bits" % (type(s).__name__))

def _ctype_bufout(buf):
    if version_info[0] < 3:
        return str(buf.raw)
    else:
        return buf.raw

def _hex_encode(buf):
    return hexlify(buf).decode('ascii')

#
# Versioning
#
def version_major():
    return int(_DLL.botan_version_major())

def version_minor():
    return int(_DLL.botan_version_minor())

def version_patch():
    return int(_DLL.botan_version_patch())

def ffi_api_version():
    return int(_DLL.botan_ffi_api_version())

def version_string():
    return _DLL.botan_version_string().decode('ascii')

#
# Utilities
#
def const_time_compare(x, y):
    len_x = len(x)
    len_y = len(y)
    if len_x != len_y:
        return False
    rc = _DLL.botan_constant_time_compare(_ctype_bits(x), _ctype_bits(y), c_size_t(len_x))
    return rc == 0

#
# RNG
#
class RandomNumberGenerator(object):
    # Can also use type "system"
    def __init__(self, rng_type='system'):
        self.__obj = c_void_p(0)
        _DLL.botan_rng_init(byref(self.__obj), _ctype_str(rng_type))

    def __del__(self):
        _DLL.botan_rng_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def reseed(self, bits=256):
        _DLL.botan_rng_reseed(self.__obj, bits)

    def reseed_from_rng(self, source_rng, bits=256):
        _DLL.botan_rng_reseed_from_rng(self.__obj, source_rng.handle_(), bits)

    def add_entropy(self, seed):
        _DLL.botan_rng_add_entropy(self.__obj, _ctype_bits(seed), len(seed))

    def get(self, length):
        out = create_string_buffer(length)
        l = c_size_t(length)
        _DLL.botan_rng_get(self.__obj, out, l)
        return _ctype_bufout(out)

#
# Block cipher
#
class BlockCipher(object):
    def __init__(self, algo):

        if isinstance(algo, c_void_p):
            self.__obj = algo
        else:
            flags = c_uint32(0) # always zero in this API version
            self.__obj = c_void_p(0)
            _DLL.botan_block_cipher_init(byref(self.__obj), _ctype_str(algo), flags)

        min_keylen = c_size_t(0)
        max_keylen = c_size_t(0)
        mod_keylen = c_size_t(0)
        _DLL.botan_block_cipher_get_keyspec(self.__obj, byref(min_keylen), byref(max_keylen), byref(mod_keylen))

        self.__min_keylen = min_keylen.value
        self.__max_keylen = max_keylen.value
        self.__mod_keylen = mod_keylen.value

        self.__block_size = _DLL.botan_block_cipher_block_size(self.__obj)

    def __del__(self):
        _DLL.botan_block_cipher_destroy(self.__obj)

    def set_key(self, key):
        _DLL.botan_block_cipher_set_key(self.__obj, key, len(key))

    def encrypt(self, pt):
        if len(pt) % self.block_size() != 0:
            raise Exception("Invalid input must be multiple of block size")

        blocks = c_size_t(len(pt) // self.block_size())
        output = create_string_buffer(len(pt))
        _DLL.botan_block_cipher_encrypt_blocks(self.__obj, pt, output, blocks)
        return output

    def decrypt(self, ct):
        if len(ct) % self.block_size() != 0:
            raise Exception("Invalid input must be multiple of block size")

        blocks = c_size_t(len(ct) // self.block_size())
        output = create_string_buffer(len(ct))
        _DLL.botan_block_cipher_decrypt_blocks(self.__obj, ct, output, blocks)
        return output

    def algo_name(self):
        return _call_fn_returning_str(32, lambda b, bl: _DLL.botan_block_cipher_name(self.__obj, b, bl))

    def clear(self):
        _DLL.botan_block_cipher_clear(self.__obj)

    def block_size(self):
        return self.__block_size

    def minimum_keylength(self):
        return self.__min_keylen

    def maximum_keylength(self):
        return self.__max_keylen


#
# Hash function
#
class HashFunction(object):
    def __init__(self, algo):

        if isinstance(algo, c_void_p):
            self.__obj = algo
        else:
            flags = c_uint32(0) # always zero in this API version
            self.__obj = c_void_p(0)
            _DLL.botan_hash_init(byref(self.__obj), _ctype_str(algo), flags)

        self.__output_length = _call_fn_returning_sz(lambda l: _DLL.botan_hash_output_length(self.__obj, l))
        self.__block_size = _call_fn_returning_sz(lambda l: _DLL.botan_hash_block_size(self.__obj, l))

    def __del__(self):
        _DLL.botan_hash_destroy(self.__obj)

    def copy_state(self):
        copy = c_void_p(0)
        _DLL.botan_hash_copy_state(byref(copy), self.__obj)
        return HashFunction(copy)

    def algo_name(self):
        return _call_fn_returning_str(32, lambda b, bl: _DLL.botan_hash_name(self.__obj, b, bl))

    def clear(self):
        _DLL.botan_hash_clear(self.__obj)

    def output_length(self):
        return self.__output_length

    def block_size(self):
        return self.__block_size

    def update(self, x):
        _DLL.botan_hash_update(self.__obj, _ctype_bits(x), len(x))

    def final(self):
        out = create_string_buffer(self.output_length())
        _DLL.botan_hash_final(self.__obj, out)
        return _ctype_bufout(out)

#
# Message authentication codes
#
class MsgAuthCode(object):
    def __init__(self, algo):
        flags = c_uint32(0) # always zero in this API version
        self.__obj = c_void_p(0)
        _DLL.botan_mac_init(byref(self.__obj), _ctype_str(algo), flags)

        min_keylen = c_size_t(0)
        max_keylen = c_size_t(0)
        mod_keylen = c_size_t(0)
        _DLL.botan_mac_get_keyspec(self.__obj, byref(min_keylen), byref(max_keylen), byref(mod_keylen))

        self.__min_keylen = min_keylen.value
        self.__max_keylen = max_keylen.value
        self.__mod_keylen = mod_keylen.value

        output_length = c_size_t(0)
        _DLL.botan_mac_output_length(self.__obj, byref(output_length))
        self.__output_length = output_length.value

    def __del__(self):
        _DLL.botan_mac_destroy(self.__obj)

    def clear(self):
        _DLL.botan_mac_clear(self.__obj)

    def algo_name(self):
        return _call_fn_returning_str(32, lambda b, bl: _DLL.botan_mac_name(self.__obj, b, bl))

    def output_length(self):
        return self.__output_length

    def minimum_keylength(self):
        return self.__min_keylen

    def maximum_keylength(self):
        return self.__max_keylen

    def set_key(self, key):
        _DLL.botan_mac_set_key(self.__obj, key, len(key))

    def update(self, x):
        _DLL.botan_mac_update(self.__obj, x, len(x))

    def final(self):
        out = create_string_buffer(self.output_length())
        _DLL.botan_mac_final(self.__obj, out)
        return _ctype_bufout(out)

class SymmetricCipher(object):
    def __init__(self, algo, encrypt=True):
        flags = 0 if encrypt else 1
        self.__obj = c_void_p(0)
        _DLL.botan_cipher_init(byref(self.__obj), _ctype_str(algo), flags)

    def __del__(self):
        _DLL.botan_cipher_destroy(self.__obj)

    def algo_name(self):
        return _call_fn_returning_str(32, lambda b, bl: _DLL.botan_cipher_name(self.__obj, b, bl))

    def default_nonce_length(self):
        l = c_size_t(0)
        _DLL.botan_cipher_get_default_nonce_length(self.__obj, byref(l))
        return l.value

    def update_granularity(self):
        l = c_size_t(0)
        _DLL.botan_cipher_get_update_granularity(self.__obj, byref(l))
        return l.value

    def key_length(self):
        kmin = c_size_t(0)
        kmax = c_size_t(0)
        _DLL.botan_cipher_query_keylen(self.__obj, byref(kmin), byref(kmax))
        return kmin.value, kmax.value

    def minimum_keylength(self):
        l = c_size_t(0)
        _DLL.botan_cipher_get_keyspec(self.__obj, byref(l), None, None)
        return l.value

    def maximum_keylength(self):
        l = c_size_t(0)
        _DLL.botan_cipher_get_keyspec(self.__obj, None, byref(l), None)
        return l.value

    def tag_length(self):
        l = c_size_t(0)
        _DLL.botan_cipher_get_tag_length(self.__obj, byref(l))
        return l.value

    def is_authenticated(self):
        return self.tag_length() > 0

    def valid_nonce_length(self, nonce_len):
        rc = _DLL.botan_cipher_valid_nonce_length(self.__obj, nonce_len)
        return rc == 1

    def reset(self):
        _DLL.botan_cipher_reset(self.__obj)

    def clear(self):
        _DLL.botan_cipher_clear(self.__obj)

    def set_key(self, key):
        _DLL.botan_cipher_set_key(self.__obj, key, len(key))

    def set_assoc_data(self, ad):
        _DLL.botan_cipher_set_associated_data(self.__obj, ad, len(ad))

    def start(self, nonce):
        _DLL.botan_cipher_start(self.__obj, nonce, len(nonce))

    def _update(self, txt, final):

        inp = txt if txt else ''
        inp_sz = c_size_t(len(inp))
        inp_consumed = c_size_t(0)
        out = create_string_buffer(inp_sz.value + (self.tag_length() if final else 0))
        out_sz = c_size_t(len(out))
        out_written = c_size_t(0)
        flags = c_uint32(1 if final else 0)

        _DLL.botan_cipher_update(self.__obj, flags,
                                 out, out_sz, byref(out_written),
                                 _ctype_bits(inp), inp_sz, byref(inp_consumed))

        # buffering not supported yet
        assert inp_consumed.value == inp_sz.value
        return out.raw[0:int(out_written.value)]

    def update(self, txt):
        return self._update(txt, False)

    def finish(self, txt=None):
        return self._update(txt, True)

def bcrypt(passwd, rng_obj, work_factor=10):
    """
    Bcrypt password hashing
    """
    out_len = c_size_t(64)
    out = create_string_buffer(out_len.value)
    flags = c_uint32(0)
    _DLL.botan_bcrypt_generate(out, byref(out_len), _ctype_str(passwd),
                               rng_obj.handle_(), c_size_t(work_factor), flags)
    b = out.raw[0:int(out_len.value)-1]
    if b[-1] == '\x00':
        b = b[:-1]
    return _ctype_to_str(b)

def check_bcrypt(passwd, passwd_hash):
    rc = _DLL.botan_bcrypt_is_valid(_ctype_str(passwd), _ctype_str(passwd_hash))
    return rc == 0

#
# PBKDF
#
def pbkdf(algo, password, out_len, iterations=10000, salt=None):
    if salt is None:
        salt = RandomNumberGenerator().get(12)

    out_buf = create_string_buffer(out_len)

    _DLL.botan_pwdhash(_ctype_str(algo), iterations, 0, 0,
                       out_buf, out_len,
                       _ctype_str(password), len(password),
                       salt, len(salt))
    return (salt, iterations, out_buf.raw)

def pbkdf_timed(algo, password, out_len, ms_to_run=300, salt=None):
    if salt is None:
        salt = RandomNumberGenerator().get(12)

    out_buf = create_string_buffer(out_len)
    iterations = c_size_t(0)

    _DLL.botan_pwdhash_timed(_ctype_str(algo), c_uint32(ms_to_run),
                             byref(iterations), None, None,
                             out_buf, out_len,
                             _ctype_str(password), len(password),
                             salt, len(salt))
    return (salt, iterations.value, out_buf.raw)

#
# Scrypt
#
def scrypt(out_len, password, salt, n=1024, r=8, p=8):
    out_buf = create_string_buffer(out_len)
    _DLL.botan_pwdhash(_ctype_str("Scrypt"), n, r, p,
                       out_buf, out_len,
                       _ctype_str(password), len(password),
                       _ctype_bits(salt), len(salt))

    return out_buf.raw

#
# KDF
#
def kdf(algo, secret, out_len, salt, label):
    out_buf = create_string_buffer(out_len)
    out_sz = c_size_t(out_len)
    _DLL.botan_kdf(_ctype_str(algo), out_buf, out_sz,
                   secret, len(secret),
                   salt, len(salt),
                   label, len(label))
    return out_buf.raw[0:int(out_sz.value)]

#
# Public key
#
class PublicKey(object): # pylint: disable=invalid-name

    def __init__(self, obj=c_void_p(0)):
        self.__obj = obj

    @classmethod
    def load(cls, val):
        obj = c_void_p(0)
        _DLL.botan_pubkey_load(byref(obj), _ctype_bits(val), len(val))
        return PublicKey(obj)

    @classmethod
    def load_rsa(cls, n, e):
        obj = c_void_p(0)
        n = MPI(n)
        e = MPI(e)
        _DLL.botan_pubkey_load_rsa(byref(obj), n.handle_(), e.handle_())
        return PublicKey(obj)

    @classmethod
    def load_dsa(cls, p, q, g, y):
        obj = c_void_p(0)
        p = MPI(p)
        q = MPI(q)
        g = MPI(g)
        y = MPI(y)
        _DLL.botan_pubkey_load_dsa(byref(obj), p.handle_(), q.handle_(), g.handle_(), y.handle_())
        return PublicKey(obj)

    @classmethod
    def load_dh(cls, p, g, y):
        obj = c_void_p(0)
        p = MPI(p)
        g = MPI(g)
        y = MPI(y)
        _DLL.botan_pubkey_load_dh(byref(obj), p.handle_(), g.handle_(), y.handle_())
        return PublicKey(obj)

    @classmethod
    def load_elgamal(cls, p, q, g, y):
        obj = c_void_p(0)
        p = MPI(p)
        q = MPI(q)
        g = MPI(g)
        y = MPI(y)
        _DLL.botan_pubkey_load_elgamal(byref(obj), p.handle_(), q.handle_(), g.handle_(), y.handle_())
        return PublicKey(obj)

    @classmethod
    def load_ecdsa(cls, curve, pub_x, pub_y):
        obj = c_void_p(0)
        pub_x = MPI(pub_x)
        pub_y = MPI(pub_y)
        _DLL.botan_pubkey_load_ecdsa(byref(obj), pub_x.handle_(), pub_y.handle_(), _ctype_str(curve))
        return PublicKey(obj)

    @classmethod
    def load_ecdh(cls, curve, pub_x, pub_y):
        obj = c_void_p(0)
        pub_x = MPI(pub_x)
        pub_y = MPI(pub_y)
        _DLL.botan_pubkey_load_ecdh(byref(obj), pub_x.handle_(), pub_y.handle_(), _ctype_str(curve))
        return PublicKey(obj)

    @classmethod
    def load_sm2(cls, curve, pub_x, pub_y):
        obj = c_void_p(0)
        pub_x = MPI(pub_x)
        pub_y = MPI(pub_y)
        _DLL.botan_pubkey_load_sm2(byref(obj), pub_x.handle_(), pub_y.handle_(), _ctype_str(curve))
        return PublicKey(obj)

    def __del__(self):
        _DLL.botan_pubkey_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def check_key(self, rng_obj, strong=True):
        flags = 1 if strong else 0
        rc = _DLL.botan_pubkey_check_key(self.__obj, rng_obj.handle_(), flags)
        return rc == 0

    def estimated_strength(self):
        r = c_size_t(0)
        _DLL.botan_pubkey_estimated_strength(self.__obj, byref(r))
        return r.value

    def algo_name(self):
        return _call_fn_returning_str(32, lambda b, bl: _DLL.botan_pubkey_algo_name(self.__obj, b, bl))

    def export(self, pem=False):
        if pem:
            return _call_fn_returning_str(4096, lambda b, bl: _DLL.botan_pubkey_export(self.__obj, b, bl, 1))
        else:
            return _call_fn_returning_vec(4096, lambda b, bl: _DLL.botan_pubkey_export(self.__obj, b, bl, 0))

    def encoding(self, pem=False):
        return self.export(pem)

    def to_der(self):
        return self.export(False)

    def to_pem(self):
        return self.export(True)

    def fingerprint(self, hash_algorithm='SHA-256'):
        n = HashFunction(hash_algorithm).output_length()
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)

        _DLL.botan_pubkey_fingerprint(self.__obj, _ctype_str(hash_algorithm), buf, byref(buf_len))
        return _hex_encode(buf[0:int(buf_len.value)])

    def get_field(self, field_name):
        v = MPI()
        _DLL.botan_pubkey_get_field(v.handle_(), self.__obj, _ctype_str(field_name))
        return int(v)

#
# Private Key
#
class PrivateKey(object):

    def __init__(self, obj=c_void_p(0)):
        self.__obj = obj

    @classmethod
    def load(cls, val, passphrase=""):
        obj = c_void_p(0)
        rng_obj = c_void_p(0) # unused in recent versions
        _DLL.botan_privkey_load(byref(obj), rng_obj, _ctype_bits(val), len(val), _ctype_str(passphrase))
        return PrivateKey(obj)

    @classmethod
    def create(cls, algo, params, rng_obj):
        if algo == 'rsa':
            algo = 'RSA'
            params = "%d" % (params)
        elif algo == 'ecdsa':
            algo = 'ECDSA'
        elif algo in ['ecdh', 'ECDH']:
            if params == 'curve25519':
                algo = 'Curve25519'
                params = ''
            else:
                algo = 'ECDH'
        elif algo in ['mce', 'mceliece']:
            algo = 'McEliece'
            params = "%d,%d" % (params[0], params[1])

        obj = c_void_p(0)
        _DLL.botan_privkey_create(byref(obj), _ctype_str(algo), _ctype_str(params), rng_obj.handle_())
        return PrivateKey(obj)

    @classmethod
    def load_rsa(cls, p, q, e):
        obj = c_void_p(0)
        p = MPI(p)
        q = MPI(q)
        e = MPI(e)
        _DLL.botan_privkey_load_rsa(byref(obj), p.handle_(), q.handle_(), e.handle_())
        return PrivateKey(obj)

    @classmethod
    def load_dsa(cls, p, q, g, x):
        obj = c_void_p(0)
        p = MPI(p)
        q = MPI(q)
        g = MPI(g)
        x = MPI(x)
        _DLL.botan_privkey_load_dsa(byref(obj), p.handle_(), q.handle_(), g.handle_(), x.handle_())
        return PrivateKey(obj)

    @classmethod
    def load_dh(cls, p, g, x):
        obj = c_void_p(0)
        p = MPI(p)
        g = MPI(g)
        x = MPI(x)
        _DLL.botan_privkey_load_dh(byref(obj), p.handle_(), g.handle_(), x.handle_())
        return PrivateKey(obj)

    @classmethod
    def load_elgamal(cls, p, q, g, x):
        obj = c_void_p(0)
        p = MPI(p)
        q = MPI(q)
        g = MPI(g)
        x = MPI(x)
        _DLL.botan_privkey_load_elgamal(byref(obj), p.handle_(), q.handle_(), g.handle_(), x.handle_())
        return PrivateKey(obj)

    @classmethod
    def load_ecdsa(cls, curve, x):
        obj = c_void_p(0)
        x = MPI(x)
        _DLL.botan_privkey_load_ecdsa(byref(obj), x.handle_(), _ctype_str(curve))
        return PrivateKey(obj)

    @classmethod
    def load_ecdh(cls, curve, x):
        obj = c_void_p(0)
        x = MPI(x)
        _DLL.botan_privkey_load_ecdh(byref(obj), x.handle_(), _ctype_str(curve))
        return PrivateKey(obj)

    @classmethod
    def load_sm2(cls, curve, x):
        obj = c_void_p(0)
        x = MPI(x)
        _DLL.botan_privkey_load_sm2(byref(obj), x.handle_(), _ctype_str(curve))
        return PrivateKey(obj)

    def __del__(self):
        _DLL.botan_privkey_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def check_key(self, rng_obj, strong=True):
        flags = 1 if strong else 0
        rc = _DLL.botan_privkey_check_key(self.__obj, rng_obj.handle_(), flags)
        return rc == 0

    def algo_name(self):
        return _call_fn_returning_str(32, lambda b, bl: _DLL.botan_privkey_algo_name(self.__obj, b, bl))

    def get_public_key(self):
        pub = c_void_p(0)
        _DLL.botan_privkey_export_pubkey(byref(pub), self.__obj)
        return PublicKey(pub)

    def to_der(self):
        return self.export(False)

    def to_pem(self):
        return self.export(True)

    def export(self, pem=False):
        if pem:
            return _call_fn_returning_str(4096, lambda b, bl: _DLL.botan_privkey_export(self.__obj, b, bl, 1))
        else:
            return _call_fn_returning_vec(4096, lambda b, bl: _DLL.botan_privkey_export(self.__obj, b, bl, 0))

    def export_encrypted(self, passphrase, rng_obj, pem=False, msec=300, cipher=None, pbkdf=None): # pylint: disable=redefined-outer-name
        flags = 1 if pem else 0
        msec = c_uint32(msec)
        _iters = c_size_t(0)

        cb = lambda b, bl: _DLL.botan_privkey_export_encrypted_pbkdf_msec(
            self.__obj, b, bl, rng_obj.handle_(), _ctype_str(passphrase),
            msec, byref(_iters), _ctype_str(cipher), _ctype_str(pbkdf), flags)

        if pem:
            return _call_fn_returning_str(8192, cb)
        else:
            return _call_fn_returning_vec(4096, cb)

    def get_field(self, field_name):
        v = MPI()
        _DLL.botan_privkey_get_field(v.handle_(), self.__obj, _ctype_str(field_name))
        return int(v)

class PKEncrypt(object):
    def __init__(self, key, padding):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        _DLL.botan_pk_op_encrypt_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        _DLL.botan_pk_op_encrypt_destroy(self.__obj)

    def encrypt(self, msg, rng_obj):
        outbuf_sz = c_size_t(0)
        _DLL.botan_pk_op_encrypt_output_length(self.__obj, len(msg), byref(outbuf_sz))
        outbuf = create_string_buffer(outbuf_sz.value)
        _DLL.botan_pk_op_encrypt(self.__obj, rng_obj.handle_(), outbuf, byref(outbuf_sz), msg, len(msg))
        return outbuf.raw[0:int(outbuf_sz.value)]


class PKDecrypt(object):
    def __init__(self, key, padding):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        _DLL.botan_pk_op_decrypt_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        _DLL.botan_pk_op_decrypt_destroy(self.__obj)

    def decrypt(self, msg):
        outbuf_sz = c_size_t(0)
        _DLL.botan_pk_op_decrypt_output_length(self.__obj, len(msg), byref(outbuf_sz))
        outbuf = create_string_buffer(outbuf_sz.value)
        _DLL.botan_pk_op_decrypt(self.__obj, outbuf, byref(outbuf_sz), _ctype_bits(msg), len(msg))
        return outbuf.raw[0:int(outbuf_sz.value)]

class PKSign(object): # pylint: disable=invalid-name
    def __init__(self, key, padding, der=False):
        self.__obj = c_void_p(0)
        flags = c_uint32(1) if der else c_uint32(0)
        _DLL.botan_pk_op_sign_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        _DLL.botan_pk_op_sign_destroy(self.__obj)

    def update(self, msg):
        _DLL.botan_pk_op_sign_update(self.__obj, _ctype_str(msg), len(msg))

    def finish(self, rng_obj):
        outbuf_sz = c_size_t(0)
        _DLL.botan_pk_op_sign_output_length(self.__obj, byref(outbuf_sz))
        outbuf = create_string_buffer(outbuf_sz.value)
        _DLL.botan_pk_op_sign_finish(self.__obj, rng_obj.handle_(), outbuf, byref(outbuf_sz))
        return outbuf.raw[0:int(outbuf_sz.value)]

class PKVerify(object):
    def __init__(self, key, padding, der=False):
        self.__obj = c_void_p(0)
        flags = c_uint32(1) if der else c_uint32(0)
        _DLL.botan_pk_op_verify_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        _DLL.botan_pk_op_verify_destroy(self.__obj)

    def update(self, msg):
        _DLL.botan_pk_op_verify_update(self.__obj, _ctype_bits(msg), len(msg))

    def check_signature(self, signature):
        rc = _DLL.botan_pk_op_verify_finish(self.__obj, _ctype_bits(signature), len(signature))
        if rc == 0:
            return True
        return False

class PKKeyAgreement(object):
    def __init__(self, key, kdf_name):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        _DLL.botan_pk_op_key_agreement_create(byref(self.__obj), key.handle_(), _ctype_str(kdf_name), flags)

        self.m_public_value = _call_fn_returning_vec(
            0, lambda b, bl: _DLL.botan_pk_op_key_agreement_export_public(key.handle_(), b, bl))

    def __del__(self):
        _DLL.botan_pk_op_key_agreement_destroy(self.__obj)

    def public_value(self):
        return self.m_public_value

    def underlying_output_length(self):
        out_len = c_size_t(0)
        _DLL.botan_pk_op_key_agreement_size(self.__obj, byref(out_len))
        return out_len.value

    def agree(self, other, key_len, salt):
        if key_len == 0:
            key_len = self.underlying_output_length()
        return _call_fn_returning_vec(key_len, lambda b, bl:
                                      _DLL.botan_pk_op_key_agreement(self.__obj, b, bl,
                                                                     other, len(other),
                                                                     salt, len(salt)))

#
# MCEIES encryption
# Must be used with McEliece keys
#
def mceies_encrypt(mce, rng_obj, aead, pt, ad):
    return _call_fn_returning_vec(len(pt) + 1024, lambda b, bl:
                                  _DLL.botan_mceies_encrypt(mce.handle_(),
                                                            rng_obj.handle_(),
                                                            _ctype_str(aead),
                                                            _ctype_bits(pt),
                                                            len(pt),
                                                            _ctype_bits(ad),
                                                            len(ad),
                                                            b, bl))

def mceies_decrypt(mce, aead, ct, ad):

    #msg = cast(msg, c_char_p)
    #ll = c_size_t(ll)

    return _call_fn_returning_vec(len(ct), lambda b, bl:
                                  _DLL.botan_mceies_decrypt(mce.handle_(),
                                                            _ctype_str(aead),
                                                            _ctype_bits(ct),
                                                            len(ct),
                                                            _ctype_bits(ad),
                                                            len(ad),
                                                            b, bl))


def _load_buf_or_file(filename, buf, file_fn, buf_fn):
    if filename is None and buf is None:
        raise BotanException("No filename or buf given")
    if filename is not None and buf is not None:
        raise BotanException("Both filename and buf given")

    obj = c_void_p(0)

    if filename is not None:
        file_fn(byref(obj), _ctype_str(filename))
    elif buf is not None:
        buf_fn(byref(obj), _ctype_bits(buf), len(buf))

    return obj


#
# X.509 certificates
#
class X509Cert(object): # pylint: disable=invalid-name
    def __init__(self, filename=None, buf=None):
        self.__obj = _load_buf_or_file(filename, buf, _DLL.botan_x509_cert_load_file, _DLL.botan_x509_cert_load)

    def __del__(self):
        _DLL.botan_x509_cert_destroy(self.__obj)

    def time_starts(self):
        starts = _call_fn_returning_str(
            16, lambda b, bl: _DLL.botan_x509_cert_get_time_starts(self.__obj, b, bl))
        if len(starts) == 13:
            # UTC time
            struct_time = strptime(starts, "%y%m%d%H%M%SZ")
        elif len(starts) == 15:
            # Generalized time
            struct_time = strptime(starts, "%Y%m%d%H%M%SZ")
        else:
            raise BotanException("Unexpected date/time format for x509 start time")

        return datetime.fromtimestamp(mktime(struct_time))

    def time_expires(self):
        expires = _call_fn_returning_str(
            16, lambda b, bl: _DLL.botan_x509_cert_get_time_expires(self.__obj, b, bl))
        if len(expires) == 13:
            # UTC time
            struct_time = strptime(expires, "%y%m%d%H%M%SZ")
        elif len(expires) == 15:
            # Generalized time
            struct_time = strptime(expires, "%Y%m%d%H%M%SZ")
        else:
            raise BotanException("Unexpected date/time format for x509 expire time")

        return datetime.fromtimestamp(mktime(struct_time))

    def to_string(self):
        return _call_fn_returning_str(
            4096, lambda b, bl: _DLL.botan_x509_cert_to_string(self.__obj, b, bl))

    def fingerprint(self, hash_algo='SHA-256'):
        n = HashFunction(hash_algo).output_length() * 3
        return _call_fn_returning_str(
            n, lambda b, bl: _DLL.botan_x509_cert_get_fingerprint(self.__obj, _ctype_str(hash_algo), b, bl))

    def serial_number(self):
        return _call_fn_returning_vec(
            32, lambda b, bl: _DLL.botan_x509_cert_get_serial_number(self.__obj, b, bl))

    def authority_key_id(self):
        return _call_fn_returning_vec(
            32, lambda b, bl: _DLL.botan_x509_cert_get_authority_key_id(self.__obj, b, bl))

    def subject_key_id(self):
        return _call_fn_returning_vec(
            32, lambda b, bl: _DLL.botan_x509_cert_get_subject_key_id(self.__obj, b, bl))

    def subject_public_key_bits(self):
        return _call_fn_returning_vec(
            512, lambda b, bl: _DLL.botan_x509_cert_get_public_key_bits(self.__obj, b, bl))

    def subject_public_key(self):
        pub = c_void_p(0)
        _DLL.botan_x509_cert_get_public_key(self.__obj, byref(pub))
        return PublicKey(pub)

    def subject_dn(self, key, index):
        return _call_fn_returning_str(
            0, lambda b, bl: _DLL.botan_x509_cert_get_subject_dn(self.__obj, _ctype_str(key), index, b, bl))

    def issuer_dn(self, key, index):
        return _call_fn_returning_str(
            0, lambda b, bl: _DLL.botan_x509_cert_get_issuer_dn(self.__obj, _ctype_str(key), index, b, bl))

    def hostname_match(self, hostname):
        rc = _DLL.botan_x509_cert_hostname_match(self.__obj, _ctype_str(hostname))
        return rc == 0

    def not_before(self):
        time = c_uint64(0)
        _DLL.botan_x509_cert_not_before(self.__obj, byref(time))
        return time.value

    def not_after(self):
        time = c_uint64(0)
        _DLL.botan_x509_cert_not_after(self.__obj, byref(time))
        return time.value

    def allowed_usage(self, usage_list):
        usage_values = {"NO_CONSTRAINTS": 0,
                        "DIGITAL_SIGNATURE": 32768,
                        "NON_REPUDIATION": 16384,
                        "KEY_ENCIPHERMENT": 8192,
                        "DATA_ENCIPHERMENT": 4096,
                        "KEY_AGREEMENT": 2048,
                        "KEY_CERT_SIGN": 1024,
                        "CRL_SIGN": 512,
                        "ENCIPHER_ONLY": 256,
                        "DECIPHER_ONLY": 128}
        usage = 0
        for u in usage_list:
            if u not in usage_values:
                return False
            usage += usage_values[u]

        rc = _DLL.botan_x509_cert_allowed_usage(self.__obj, c_uint(usage))
        return rc == 0

    def handle_(self):
        return self.__obj

    def verify(self,
               intermediates=None,
               trusted=None,
               trusted_path=None,
               required_strength=0,
               hostname=None,
               reference_time=0,
               crls=None):
        #pylint: disable=too-many-locals

        if intermediates is not None:
            c_intermediates = len(intermediates) * c_void_p
            arr_intermediates = c_intermediates()
            for i, ca in enumerate(intermediates):
                arr_intermediates[i] = ca.handle_()
            len_intermediates = c_size_t(len(intermediates))
        else:
            arr_intermediates = c_void_p(0)
            len_intermediates = c_size_t(0)

        if trusted is not None:
            c_trusted = len(trusted) * c_void_p
            arr_trusted = c_trusted()
            for i, ca in enumerate(trusted):
                arr_trusted[i] = ca.handle_()
            len_trusted = c_size_t(len(trusted))
        else:
            arr_trusted = c_void_p(0)
            len_trusted = c_size_t(0)

        if crls is not None:
            c_crls = len(crls) * c_void_p
            arr_crls = c_crls()
            for i, crl in enumerate(crls):
                arr_crls[i] = crl.handle_()
            len_crls = c_size_t(len(crls))
        else:
            arr_crls = c_void_p(0)
            len_crls = c_size_t(0)

        error_code = c_int(0)

        _DLL.botan_x509_cert_verify_with_crl(byref(error_code),
                                             self.__obj,
                                             byref(arr_intermediates),
                                             len_intermediates,
                                             byref(arr_trusted),
                                             len_trusted,
                                             byref(arr_crls),
                                             len_crls,
                                             _ctype_str(trusted_path),
                                             c_size_t(required_strength),
                                             _ctype_str(hostname),
                                             c_uint64(reference_time))

        return error_code.value

    @classmethod
    def validation_status(cls, error_code):
        return _ctype_to_str(_DLL.botan_x509_cert_validation_status(c_int(error_code)))

    def is_revoked(self, crl):
        rc = _DLL.botan_x509_is_revoked(crl.handle_(), self.__obj)
        return rc == 0


#
# X.509 Certificate revocation lists
#
class X509CRL(object):
    def __init__(self, filename=None, buf=None):
        self.__obj = _load_buf_or_file(filename, buf, _DLL.botan_x509_crl_load_file, _DLL.botan_x509_crl_load)

    def __del__(self):
        _DLL.botan_x509_crl_destroy(self.__obj)

    def handle_(self):
        return self.__obj


class MPI(object): # pylint: disable=too-many-public-methods

    def __init__(self, initial_value=None, radix=None):

        self.__obj = c_void_p(0)
        _DLL.botan_mp_init(byref(self.__obj))

        if initial_value is None:
            pass # left as zero
        elif isinstance(initial_value, MPI):
            _DLL.botan_mp_set_from_mp(self.__obj, initial_value.handle_())
        elif radix is not None:
            _DLL.botan_mp_set_from_radix_str(self.__obj, _ctype_str(initial_value), c_size_t(radix))
        elif isinstance(initial_value, str):
            _DLL.botan_mp_set_from_str(self.__obj, _ctype_str(initial_value))
        else:
            # For int or long (or whatever else), try converting to string:
            _DLL.botan_mp_set_from_str(self.__obj, _ctype_str(str(initial_value)))

    @classmethod
    def random(cls, rng_obj, bits):
        bn = MPI()
        _DLL.botan_mp_rand_bits(bn.handle_(), rng_obj.handle_(), c_size_t(bits))
        return bn

    @classmethod
    def random_range(cls, rng_obj, lower, upper):
        bn = MPI()
        _DLL.botan_mp_rand_range(bn.handle_(), rng_obj.handle_(), lower.handle_(), upper.handle_())
        return bn

    def __del__(self):
        _DLL.botan_mp_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def __int__(self):
        out = create_string_buffer(2*self.byte_count() + 1)
        _DLL.botan_mp_to_hex(self.__obj, out)
        val = int(out.value, 16)
        if self.is_negative():
            return -val
        else:
            return val

    def __repr__(self):
        # Should have a better size estimate than this ...
        out_len = c_size_t(self.bit_count() // 2)
        out = create_string_buffer(out_len.value)

        _DLL.botan_mp_to_str(self.__obj, c_uint8(10), out, byref(out_len))

        out = out.raw[0:int(out_len.value)]
        if out[-1] == '\x00':
            out = out[:-1]
            s = _ctype_to_str(out)
        if s[0] == '0':
            return s[1:]
        else:
            return s

    def to_bytes(self):
        byte_count = self.byte_count()
        out_len = c_size_t(byte_count)
        out = create_string_buffer(out_len.value)
        _DLL.botan_mp_to_bin(self.__obj, out, byref(out_len))
        assert out_len.value == byte_count
        return out

    def is_negative(self):
        rc = _DLL.botan_mp_is_negative(self.__obj)
        return rc == 1

    def is_positive(self):
        rc = _DLL.botan_mp_is_positive(self.__obj)
        return rc == 1

    def is_zero(self):
        rc = _DLL.botan_mp_is_zero(self.__obj)
        return rc == 1

    def is_odd(self):
        return self.get_bit(0) == 1

    def is_even(self):
        return self.get_bit(0) == 0

    def flip_sign(self):
        _DLL.botan_mp_flip_sign(self.__obj)

    def cmp(self, other):
        r = c_int(0)
        _DLL.botan_mp_cmp(byref(r), self.__obj, other.handle_())
        return r.value

    def __hash__(self):
        return hash(self.to_bytes())

    def __eq__(self, other):
        return self.cmp(other) == 0

    def __ne__(self, other):
        return self.cmp(other) != 0

    def __lt__(self, other):
        return self.cmp(other) < 0

    def __le__(self, other):
        return self.cmp(other) <= 0

    def __gt__(self, other):
        return self.cmp(other) > 0

    def __ge__(self, other):
        return self.cmp(other) >= 0

    def __add__(self, other):
        r = MPI()
        _DLL.botan_mp_add(r.handle_(), self.__obj, other.handle_())
        return r

    def __iadd__(self, other):
        _DLL.botan_mp_add(self.__obj, self.__obj, other.handle_())
        return self

    def __sub__(self, other):
        r = MPI()
        _DLL.botan_mp_sub(r.handle_(), self.__obj, other.handle_())
        return r

    def __isub__(self, other):
        _DLL.botan_mp_sub(self.__obj, self.__obj, other.handle_())
        return self

    def __mul__(self, other):
        r = MPI()
        _DLL.botan_mp_mul(r.handle_(), self.__obj, other.handle_())
        return r

    def __imul__(self, other):
        _DLL.botan_mp_mul(self.__obj, self.__obj, other.handle_())
        return self

    def __divmod__(self, other):
        d = MPI()
        q = MPI()
        _DLL.botan_mp_div(d.handle_(), q.handle_(), self.__obj, other.handle_())
        return (d, q)

    def __mod__(self, other):
        d = MPI()
        q = MPI()
        _DLL.botan_mp_div(d.handle_(), q.handle_(), self.__obj, other.handle_())
        return q

    def __lshift__(self, shift):
        shift = c_size_t(shift)
        r = MPI()
        _DLL.botan_mp_lshift(r.handle_(), self.__obj, shift)
        return r

    def __ilshift__(self, shift):
        shift = c_size_t(shift)
        _DLL.botan_mp_lshift(self.__obj, self.__obj, shift)
        return self

    def __rshift__(self, shift):
        shift = c_size_t(shift)
        r = MPI()
        _DLL.botan_mp_rshift(r.handle_(), self.__obj, shift)
        return r

    def __irshift__(self, shift):
        shift = c_size_t(shift)
        _DLL.botan_mp_rshift(self.__obj, self.__obj, shift)
        return self

    def mod_mul(self, other, modulus):
        r = MPI()
        _DLL.botan_mp_mod_mul(r.handle_(), self.__obj, other.handle_(), modulus.handle_())
        return r

    def gcd(self, other):
        r = MPI()
        _DLL.botan_mp_gcd(r.handle_(), self.__obj, other.handle_())
        return r

    def pow_mod(self, exponent, modulus):
        r = MPI()
        _DLL.botan_mp_powmod(r.handle_(), self.__obj, exponent.handle_(), modulus.handle_())
        return r

    def is_prime(self, rng_obj, prob=128):
        return _DLL.botan_mp_is_prime(self.__obj, rng_obj.handle_(), c_size_t(prob)) == 1

    def inverse_mod(self, modulus):
        r = MPI()
        _DLL.botan_mp_mod_inverse(r.handle_(), self.__obj, modulus.handle_())
        return r

    def bit_count(self):
        b = c_size_t(0)
        _DLL.botan_mp_num_bits(self.__obj, byref(b))
        return b.value

    def byte_count(self):
        b = c_size_t(0)
        _DLL.botan_mp_num_bytes(self.__obj, byref(b))
        return b.value

    def get_bit(self, bit):
        return _DLL.botan_mp_get_bit(self.__obj, c_size_t(bit)) == 1

    def clear_bit(self, bit):
        _DLL.botan_mp_clear_bit(self.__obj, c_size_t(bit))

    def set_bit(self, bit):
        _DLL.botan_mp_set_bit(self.__obj, c_size_t(bit))

class FormatPreservingEncryptionFE1(object):

    def __init__(self, modulus, key, rounds=5, compat_mode=False):
        flags = c_uint32(1 if compat_mode else 0)
        self.__obj = c_void_p(0)
        _DLL.botan_fpe_fe1_init(byref(self.__obj), modulus.handle_(), key, len(key), c_size_t(rounds), flags)

    def __del__(self):
        _DLL.botan_fpe_destroy(self.__obj)

    def encrypt(self, msg, tweak):
        r = MPI(msg)
        _DLL.botan_fpe_encrypt(self.__obj, r.handle_(), _ctype_bits(tweak), len(tweak))
        return r

    def decrypt(self, msg, tweak):
        r = MPI(msg)
        _DLL.botan_fpe_decrypt(self.__obj, r.handle_(), _ctype_bits(tweak), len(tweak))
        return r

class HOTP(object):
    def __init__(self, key, digest="SHA-1", digits=6):
        self.__obj = c_void_p(0)
        _DLL.botan_hotp_init(byref(self.__obj), key, len(key), _ctype_str(digest), digits)

    def __del__(self):
        _DLL.botan_hotp_destroy(self.__obj)

    def generate(self, counter):
        code = c_uint32(0)
        _DLL.botan_hotp_generate(self.__obj, byref(code), counter)
        return code.value

    def check(self, code, counter, resync_range=0):
        next_ctr = c_uint64(0)
        rc = _DLL.botan_hotp_check(self.__obj, byref(next_ctr), code, counter, resync_range)
        if rc == 0:
            return (True, next_ctr.value)
        else:
            return (False, counter)

class TOTP(object):
    def __init__(self, key, digest="SHA-1", digits=6, timestep=30):
        self.__obj = c_void_p(0)
        _DLL.botan_totp_init(byref(self.__obj), key, len(key), _ctype_str(digest), digits, timestep)

    def __del__(self):
        _DLL.botan_totp_destroy(self.__obj)

    def generate(self, timestamp=None):
        if timestamp is None:
            timestamp = int(system_time())
        code = c_uint32(0)
        _DLL.botan_totp_generate(self.__obj, byref(code), timestamp)
        return code.value

    def check(self, code, timestamp=None, acceptable_drift=0):
        if timestamp is None:
            timestamp = int(system_time())
        rc = _DLL.botan_totp_check(self.__obj, code, timestamp, acceptable_drift)
        if rc == 0:
            return True
        return False

def nist_key_wrap(kek, key):
    output = create_string_buffer(len(key) + 8)
    out_len = c_size_t(len(output))
    _DLL.botan_key_wrap3394(key, len(key), kek, len(kek), output, byref(out_len))
    return output[0:int(out_len.value)]

def nist_key_unwrap(kek, wrapped):
    output = create_string_buffer(len(wrapped))
    out_len = c_size_t(len(output))
    _DLL.botan_key_unwrap3394(wrapped, len(wrapped), kek, len(kek), output, byref(out_len))
    return output[0:int(out_len.value)]

# Typedefs for compat with older versions
# Will be removed in a future major release
cipher = SymmetricCipher                  # pylint: disable=invalid-name
rng = RandomNumberGenerator               # pylint: disable=invalid-name
hash_function = HashFunction              # pylint: disable=invalid-name
message_authentication_code = MsgAuthCode # pylint: disable=invalid-name

x509_cert = X509Cert                      # pylint: disable=invalid-name
public_key = PublicKey                    # pylint: disable=invalid-name
private_key = PrivateKey                  # pylint: disable=invalid-name

pk_op_encrypt = PKEncrypt                 # pylint: disable=invalid-name
pk_op_decrypt = PKDecrypt                 # pylint: disable=invalid-name
pk_op_sign = PKSign                       # pylint: disable=invalid-name
pk_op_verify = PKVerify                   # pylint: disable=invalid-name
pk_op_key_agreement = PKKeyAgreement      # pylint: disable=invalid-name
