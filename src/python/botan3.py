#!/usr/bin/env python3

"""
Python wrapper of the botan crypto library
https://botan.randombit.net

(C) 2015,2017,2018,2019,2023 Jack Lloyd
(C) 2015 Uri  Blumenthal (extensions and patches)
(C) 2024 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity
(C) 2025 Dominik Schricker

Botan is released under the Simplified BSD License (see license.txt)

This module uses the ctypes module and is usable by programs running
under at least CPython 3.x, and PyPy

It uses botan's ffi module, which exposes a C API.
"""

from ctypes import CDLL, CFUNCTYPE, POINTER, byref, create_string_buffer, \
    c_void_p, c_size_t, c_uint8, c_uint32, c_uint64, c_int, c_uint, c_char, c_char_p, addressof
from typing import Callable

from sys import platform
from time import strptime, mktime, time as system_time
from binascii import hexlify
from datetime import datetime
from collections.abc import Iterable

# This Python module requires the FFI API version introduced in Botan 3.8.0
BOTAN_FFI_VERSION = 20250506

#
# Base exception for all exceptions raised from this module
#
class BotanException(Exception):

    def __init__(self, message, rc=0):

        self.__rc = rc

        if rc == 0:
            super().__init__(message)
        else:
            exn_msg = _DLL.botan_error_last_exception_message().decode('ascii')
            err_descr = _DLL.botan_error_description(rc).decode('ascii')

            formatted_msg = "%s: %d (%s)" % (message, rc, err_descr)
            if exn_msg != "":
                formatted_msg += ': ' + exn_msg

            super().__init__(formatted_msg)

    def error_code(self):
        return self.__rc

#
# Module initialization
#

def _load_botan_dll(expected_version):

    possible_dll_names = []

    if platform in ['win32', 'cygwin', 'msys']:
        possible_dll_names.append('botan-3.dll')
        possible_dll_names.append('libbotan-3.dll')
        possible_dll_names.append('botan.dll')
    elif platform in ['darwin', 'macos']:
        possible_dll_names.append('libbotan-3.dylib')
    else:
        # assumed to be some Unix/Linux system
        possible_dll_names.append('libbotan-3.so')

        min_minor = 8 # minimum supported FFI
        max_minor = 32 # arbitrary but probably large enough
        possible_dll_names += ['libbotan-3.so.%d' % (v) for v in reversed(range(min_minor, max_minor))]

    for dll_name in possible_dll_names:
        try:
            dll = CDLL(dll_name)
            if hasattr(dll, 'botan_ffi_supports_api'):
                dll.botan_ffi_supports_api.argtypes = [c_uint32]
                dll.botan_ffi_supports_api.restype = c_int
                if dll.botan_ffi_supports_api(expected_version) == 0:
                    return dll
        except OSError:
            pass

    raise BotanException("Could not find a usable Botan shared object library")

VIEW_BIN_CALLBACK = CFUNCTYPE(c_int, c_void_p, POINTER(c_char), c_size_t)
VIEW_STR_CALLBACK = CFUNCTYPE(c_int, c_void_p, c_char_p, c_size_t)

def _errcheck(rc, fn, _args):
    # This errcheck should only be used for int-returning functions
    assert isinstance(rc, int)

    if rc >= 0 or rc in fn.allowed_errors:
        return rc
    raise BotanException('%s failed' % (fn.__name__), rc)

def _set_prototypes(dll):
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

    dll.botan_error_last_exception_message.argtypes = []
    dll.botan_error_last_exception_message.restype = c_char_p

    # These are generated using src/scripts/dev_tools/gen_ffi_decls.py:
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
    ffi_api(dll.botan_mac_set_nonce, [c_void_p, c_char_p, c_size_t])
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
    ffi_api(dll.botan_cipher_is_authenticated, [c_void_p])
    ffi_api(dll.botan_cipher_requires_entire_message, [c_void_p])
    ffi_api(dll.botan_cipher_get_update_granularity, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_cipher_get_ideal_update_granularity, [c_void_p, POINTER(c_size_t)])
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

    # OID
    ffi_api(dll.botan_oid_destroy, [c_void_p])
    ffi_api(dll.botan_oid_from_string, [c_void_p, c_char_p])
    ffi_api(dll.botan_oid_register, [c_void_p, c_char_p])
    ffi_api(dll.botan_oid_view_string, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_oid_view_name, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_oid_equal, [c_void_p, c_void_p])
    ffi_api(dll.botan_oid_cmp, [POINTER(c_int), c_void_p, c_void_p])

    # EC Group
    ffi_api(dll.botan_ec_group_destroy, [c_void_p])
    ffi_api(dll.botan_ec_group_supports_application_specific_group, [POINTER(c_int)])
    ffi_api(dll.botan_ec_group_supports_named_group, [c_char_p, POINTER(c_int)])
    ffi_api(dll.botan_ec_group_from_params,
            [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_from_ber, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_ec_group_from_pem, [c_void_p, c_char_p])
    ffi_api(dll.botan_ec_group_from_oid, [c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_from_name, [c_void_p, c_char_p])
    ffi_api(dll.botan_ec_group_view_der, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])
    ffi_api(dll.botan_ec_group_view_pem, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_ec_group_get_curve_oid, [c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_get_p, [c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_get_a, [c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_get_b, [c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_get_g_x, [c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_get_g_y, [c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_get_order, [c_void_p, c_void_p])
    ffi_api(dll.botan_ec_group_equal, [c_void_p, c_void_p])

    #  PUBKEY
    ffi_api(dll.botan_privkey_create, [c_void_p, c_char_p, c_char_p, c_void_p])
    ffi_api(dll.botan_ec_privkey_create, [c_void_p, c_char_p, c_void_p, c_void_p])
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

    ffi_api(dll.botan_privkey_view_der, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])
    ffi_api(dll.botan_privkey_view_pem, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_privkey_view_raw, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])

    ffi_api(dll.botan_privkey_algo_name, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_privkey_export_encrypted,
            [c_void_p, c_char_p, POINTER(c_size_t), c_void_p, c_char_p, c_char_p, c_uint32])

    ffi_api(dll.botan_privkey_export_encrypted_pbkdf_msec,
            [c_void_p, c_char_p, POINTER(c_size_t), c_void_p, c_char_p, c_uint32, POINTER(c_size_t), c_char_p, c_char_p, c_uint32])
    ffi_api(dll.botan_privkey_export_encrypted_pbkdf_iter,
            [c_void_p, c_char_p, POINTER(c_size_t), c_void_p, c_char_p, c_size_t, c_char_p, c_char_p, c_uint32])

    ffi_api(dll.botan_privkey_view_encrypted_der,
            [c_void_p, c_void_p, c_char_p, c_char_p, c_char_p, c_size_t, c_void_p, VIEW_BIN_CALLBACK])
    ffi_api(dll.botan_privkey_view_encrypted_pem,
            [c_void_p, c_void_p, c_char_p, c_char_p, c_char_p, c_size_t, c_void_p, VIEW_STR_CALLBACK])

    ffi_api(dll.botan_privkey_view_encrypted_der_timed,
            [c_void_p, c_void_p, c_char_p, c_char_p, c_char_p, c_size_t, c_void_p, VIEW_BIN_CALLBACK])
    ffi_api(dll.botan_privkey_view_encrypted_pem_timed,
            [c_void_p, c_void_p, c_char_p, c_char_p, c_char_p, c_size_t, c_void_p, VIEW_STR_CALLBACK])

    ffi_api(dll.botan_privkey_export_pubkey, [c_void_p, c_void_p])
    ffi_api(dll.botan_pubkey_load, [c_void_p, c_char_p, c_size_t])

    ffi_api(dll.botan_pubkey_view_der, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])
    ffi_api(dll.botan_pubkey_view_pem, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_pubkey_view_raw, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])

    ffi_api(dll.botan_pubkey_algo_name, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pubkey_check_key, [c_void_p, c_void_p, c_uint32], [-1])
    ffi_api(dll.botan_pubkey_estimated_strength, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pubkey_fingerprint, [c_void_p, c_char_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pubkey_destroy, [c_void_p])
    ffi_api(dll.botan_pubkey_get_field, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_get_field, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_oid, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_oid, [c_void_p, c_void_p])
    ffi_api(dll.botan_privkey_stateful_operation, [c_void_p, POINTER(c_int)])
    ffi_api(dll.botan_privkey_remaining_operations, [c_void_p, POINTER(c_uint64)])
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
    ffi_api(dll.botan_privkey_load_ed448, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_ed448, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_ed448_get_privkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_ed448_get_pubkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_x25519, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_x25519, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_x25519_get_privkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_x25519_get_pubkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_x448, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_load_x448, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_x448_get_privkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_pubkey_x448_get_pubkey, [c_void_p, c_char_p])
    ffi_api(dll.botan_privkey_load_ml_dsa, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_pubkey_load_ml_dsa, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_privkey_load_slh_dsa, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_pubkey_load_slh_dsa, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_privkey_load_kyber, [c_void_p, c_char_p, c_int])
    ffi_api(dll.botan_pubkey_load_kyber, [c_void_p, c_char_p, c_int])
    ffi_api(dll.botan_privkey_view_kyber_raw_key, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])
    ffi_api(dll.botan_pubkey_view_kyber_raw_key, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])
    ffi_api(dll.botan_privkey_load_ml_kem, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_pubkey_load_ml_kem, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_privkey_load_frodokem, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_pubkey_load_frodokem, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_privkey_load_classic_mceliece, [c_void_p, c_void_p, c_int, c_char_p])
    ffi_api(dll.botan_pubkey_load_classic_mceliece, [c_void_p, c_void_p, c_int, c_char_p])
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
    ffi_api(dll.botan_pubkey_view_ec_public_point,
            [c_void_p, c_void_p, VIEW_BIN_CALLBACK])

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
    ffi_api(dll.botan_pk_op_key_agreement_view_public, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])

    ffi_api(dll.botan_pk_op_key_agreement_size, [c_void_p, POINTER(c_size_t)])
    ffi_api(dll.botan_pk_op_key_agreement,
            [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t, c_char_p, c_size_t])

    ffi_api(dll.botan_pkcs_hash_id, [c_char_p, c_char_p, POINTER(c_size_t)])

    ffi_api(dll.botan_pk_op_kem_encrypt_create, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_pk_op_kem_encrypt_destroy, [c_void_p])

    ffi_api(dll.botan_pk_op_kem_encrypt_shared_key_length, [c_void_p, c_size_t, POINTER(c_size_t)])
    ffi_api(dll.botan_pk_op_kem_encrypt_encapsulated_key_length, [c_void_p, POINTER(c_size_t)])

    ffi_api(dll.botan_pk_op_kem_encrypt_create_shared_key,
            [c_void_p, c_void_p, c_char_p, c_size_t, c_size_t,
             c_char_p, POINTER(c_size_t), c_char_p, POINTER(c_size_t)])

    ffi_api(dll.botan_pk_op_kem_decrypt_create, [c_void_p, c_void_p, c_char_p])
    ffi_api(dll.botan_pk_op_kem_decrypt_destroy, [c_void_p])

    ffi_api(dll.botan_pk_op_kem_decrypt_shared_key_length, [c_void_p, c_size_t, POINTER(c_size_t)])

    ffi_api(dll.botan_pk_op_kem_decrypt_shared_key,
            [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_size_t, c_char_p, POINTER(c_size_t)])

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
    ffi_api(dll.botan_x509_get_basic_constraints, [c_void_p, POINTER(c_int), POINTER(c_size_t)])
    ffi_api(dll.botan_x509_get_key_constraints, [c_void_p, POINTER(c_uint32)])
    ffi_api(dll.botan_x509_get_ocsp_responder, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_x509_is_self_signed, [c_void_p, POINTER(c_int)])
    ffi_api(dll.botan_x509_cert_get_public_key_bits, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_view_public_key_bits, [c_void_p, c_void_p, VIEW_BIN_CALLBACK])
    ffi_api(dll.botan_x509_cert_get_public_key, [c_void_p, c_void_p])
    ffi_api(dll.botan_x509_cert_get_issuer_dn,
            [c_void_p, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_get_subject_dn,
            [c_void_p, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_to_string, [c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_cert_view_as_string, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_x509_cert_view_pem, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_x509_cert_allowed_usage, [c_void_p, c_uint])
    ffi_api(dll.botan_x509_cert_hostname_match, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_verify,
            [POINTER(c_int), c_void_p, c_void_p, c_size_t, c_void_p, c_size_t, c_char_p, c_size_t, c_char_p, c_uint64])
    ffi_api(dll.botan_x509_ext_ip_addr_blocks_destroy, [c_void_p])
    ffi_api(dll.botan_x509_ext_create_ip_addr_blocks, [c_void_p])
    ffi_api(dll.botan_x509_ext_create_ip_addr_blocks_from_cert, [c_void_p, c_void_p])
    ffi_api(dll.botan_x509_ext_ip_addr_blocks_add_ip_addr,
            [c_void_p, c_char_p, c_char_p, c_int, POINTER(c_uint8)])
    ffi_api(dll.botan_x509_ext_ip_addr_blocks_restrict, [c_void_p, c_int, POINTER(c_uint8)])
    ffi_api(dll.botan_x509_ext_ip_addr_blocks_inherit, [c_void_p, c_int, POINTER(c_uint8)])
    ffi_api(dll.botan_x509_ext_ip_addr_blocks_get_counts, [c_void_p, POINTER(c_size_t), POINTER(c_size_t)])
    ffi_api(dll.botan_x509_ext_ip_addr_blocks_get_family,
            [c_void_p, c_int, c_size_t, POINTER(c_int), POINTER(c_uint8), POINTER(c_int), POINTER(c_size_t)])
    ffi_api(dll.botan_x509_ext_ip_addr_blocks_get_address,
            [c_void_p, c_int, c_size_t, c_size_t, c_char_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_x509_ext_as_blocks_destroy, [c_void_p])
    ffi_api(dll.botan_x509_ext_create_as_blocks, [c_void_p])
    ffi_api(dll.botan_x509_ext_create_as_blocks_from_cert, [c_void_p, c_void_p])
    ffi_api(dll.botan_x509_ext_as_blocks_add_asnum, [c_void_p, c_uint32, c_uint32])
    ffi_api(dll.botan_x509_ext_as_blocks_restrict_asnum, [c_void_p])
    ffi_api(dll.botan_x509_ext_as_blocks_inherit_asnum, [c_void_p])
    ffi_api(dll.botan_x509_ext_as_blocks_add_rdi, [c_void_p, c_uint32, c_uint32])
    ffi_api(dll.botan_x509_ext_as_blocks_restrict_rdi, [c_void_p])
    ffi_api(dll.botan_x509_ext_as_blocks_inherit_rdi, [c_void_p])
    ffi_api(dll.botan_x509_ext_as_blocks_get_asnum, [c_void_p, POINTER(c_int), POINTER(c_size_t)])
    ffi_api(dll.botan_x509_ext_as_blocks_get_asnum_at, [c_void_p, c_size_t, POINTER(c_uint32), POINTER(c_uint32)])
    ffi_api(dll.botan_x509_ext_as_blocks_get_rdi, [c_void_p, POINTER(c_int), POINTER(c_size_t)])
    ffi_api(dll.botan_x509_ext_as_blocks_get_rdi_at, [c_void_p, c_size_t, POINTER(c_uint32), POINTER(c_uint32)])
    ffi_api(dll.botan_x509_cert_params_builder_destroy, [c_void_p])
    ffi_api(dll.botan_x509_create_cert_params_builder, [c_void_p, c_char_p, POINTER(c_uint32)])
    ffi_api(dll.botan_x509_cert_params_builder_add_common_name, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_country, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_organization, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_org_unit, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_locality, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_state, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_serial_number, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_email, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_uri, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_ip, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_dns, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_xmpp, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_challenge, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_cert_params_builder_mark_as_ca_key, [c_void_p, c_size_t])
    ffi_api(dll.botan_x509_cert_params_builder_add_not_before, [c_void_p, c_uint64])
    ffi_api(dll.botan_x509_cert_params_builder_add_not_after, [c_void_p, c_uint64])
    ffi_api(dll.botan_x509_cert_params_builder_add_constraints, [c_void_p, c_uint32])
    ffi_api(dll.botan_x509_cert_params_builder_add_ex_constraint, [c_void_p, c_void_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_ext_ip_addr_blocks, [c_void_p, c_void_p])
    ffi_api(dll.botan_x509_cert_params_builder_add_ext_as_blocks, [c_void_p, c_void_p])
    ffi_api(dll.botan_x509_create_self_signed_cert,
            [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p, c_void_p])
    ffi_api(dll.botan_x509_pkcs10_req_destroy, [c_void_p])
    ffi_api(dll.botan_x509_create_pkcs10_req,
            [c_void_p, c_void_p, c_void_p, c_char_p, c_void_p])
    ffi_api(dll.botan_x509_pkcs10_req_view_pem, [c_void_p, c_void_p, VIEW_STR_CALLBACK])
    ffi_api(dll.botan_x509_sign_req,
            [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_uint64, c_uint64, c_char_p, c_char_p])

    dll.botan_x509_cert_validation_status.argtypes = [c_int]
    dll.botan_x509_cert_validation_status.restype = c_char_p

    # X509 CRL
    ffi_api(dll.botan_x509_crl_load, [c_void_p, c_char_p, c_size_t])
    ffi_api(dll.botan_x509_crl_load_file, [c_void_p, c_char_p])
    ffi_api(dll.botan_x509_crl_destroy, [c_void_p])
    ffi_api(dll.botan_x509_is_revoked, [c_void_p, c_void_p], [-1])
    ffi_api(dll.botan_x509_cert_verify_with_crl,
            [POINTER(c_int), c_void_p, c_void_p, c_size_t, c_void_p, c_size_t, c_void_p, c_size_t, c_char_p, c_size_t, c_char_p, c_uint64])

    ffi_api(dll.botan_nist_kw_enc,
            [c_char_p, c_int, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_nist_kw_dec,
            [c_char_p, c_int, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])

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

    # SRP6-a
    ffi_api(dll.botan_srp6_server_session_init, [c_void_p])
    ffi_api(dll.botan_srp6_server_session_destroy, [c_void_p])
    ffi_api(dll.botan_srp6_server_session_step1,
            [c_void_p, c_char_p, c_size_t, c_char_p, c_char_p, c_void_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_srp6_server_session_step2,
            [c_void_p, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_srp6_generate_verifier,
            [c_char_p, c_char_p, c_char_p, c_size_t, c_char_p, c_char_p, c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_srp6_client_agree,
            [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_size_t, c_char_p, c_size_t, c_void_p,
             c_char_p, POINTER(c_size_t), c_char_p, POINTER(c_size_t)])
    ffi_api(dll.botan_srp6_group_size, [c_char_p, POINTER(c_size_t)])

    # ZFEC
    ffi_api(dll.botan_zfec_encode,
            [c_size_t, c_size_t, c_char_p, c_size_t, POINTER(c_char_p)])
    ffi_api(dll.botan_zfec_decode,
            [c_size_t, c_size_t, POINTER(c_size_t), POINTER(c_char_p), c_size_t, POINTER(c_char_p)])

    # TPM2
    ffi_api(dll.botan_tpm2_supports_crypto_backend, [])
    ffi_api(dll.botan_tpm2_ctx_init, [c_void_p, c_char_p], [-40])
    ffi_api(dll.botan_tpm2_ctx_init_ex, [c_void_p, c_char_p, c_char_p], [-40])
    ffi_api(dll.botan_tpm2_ctx_enable_crypto_backend, [c_void_p, c_void_p])
    ffi_api(dll.botan_tpm2_ctx_destroy, [c_void_p], [-40])
    ffi_api(dll.botan_tpm2_rng_init, [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p])
    ffi_api(dll.botan_tpm2_unauthenticated_session_init, [c_void_p, c_void_p])
    ffi_api(dll.botan_tpm2_session_destroy, [c_void_p])

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

def _call_fn_returning_vec_pair(guess1, guess2, fn):

    buf1 = create_string_buffer(guess1)
    buf1_len = c_size_t(len(buf1))

    buf2 = create_string_buffer(guess2)
    buf2_len = c_size_t(len(buf2))

    rc = fn(buf1, byref(buf1_len), buf2, byref(buf2_len))
    if rc == -10:
        if buf1_len.value > len(buf1):
            guess1 = buf1_len.value
        if buf2_len.value > len(buf2):
            guess2 = buf2_len.value
        return _call_fn_returning_vec_pair(guess1, guess2, fn)

    assert buf1_len.value <= len(buf1)
    assert buf2_len.value <= len(buf2)
    return (buf1.raw[0:int(buf1_len.value)], buf2.raw[0:int(buf2_len.value)])

def _call_fn_returning_str(guess, fn):
    # Assumes that anything called with this is returning plain ASCII strings
    # (base64 data, algorithm names, etc)
    v = _call_fn_returning_vec(guess, fn)
    return v.decode('ascii')[:-1]

@VIEW_BIN_CALLBACK
def _view_bin_fn(_ctx, buf_val, buf_len):
    _view_bin_fn.output = buf_val[0:buf_len]
    return 0

def _call_fn_viewing_vec(fn):
    fn(None, _view_bin_fn)
    result = _view_bin_fn.output
    _view_bin_fn.output = None
    return result

@VIEW_STR_CALLBACK
def _view_str_fn(_ctx, str_val, _str_len):
    _view_str_fn.output = str_val
    return 0

def _call_fn_viewing_str(fn):
    fn(None, _view_str_fn)
    result = _view_str_fn.output.decode('utf8')
    _view_str_fn.output = None
    return result

def _ctype_str(s):
    if s is None:
        return None
    assert isinstance(s, str)
    return s.encode('utf-8')

def _ctype_to_str(s):
    return s.decode('utf-8')

def _ctype_bits(s):
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode('utf-8')
    else:
        raise Exception("Internal error - unexpected type %s provided to _ctype_bits" % (type(s).__name__))

def _ctype_bufout(buf):
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
    xbits = _ctype_bits(x)
    ybits = _ctype_bits(y)
    len_x = len(xbits)
    len_y = len(ybits)
    if len_x != len_y:
        return False
    rc = _DLL.botan_constant_time_compare(xbits, ybits, c_size_t(len_x))
    return rc == 0

#
# TPM2
#

class TPM2Object:
    def __init__(self, obj: c_void_p, destroyer: Callable[[c_void_p], None]):
        self.__obj = obj
        self.__destroyer = destroyer

    def __del__(self):
        if hasattr(self, '__obj') and hasattr(self, '__destroyer'):
            self.__destroyer(self.__obj)

    def handle_(self):
        return self.__obj

class TPM2Context(TPM2Object):
    """TPM 2.0 Context object"""

    def __init__(self, tcti_name_maybe_with_conf: str = None, tcti_conf: str = None):
        """Construct a TPM2Context object with optional TCTI name and configuration."""

        obj = c_void_p(0)
        if tcti_conf is not None:
            rc = _DLL.botan_tpm2_ctx_init_ex(byref(obj), _ctype_str(tcti_name_maybe_with_conf), _ctype_str(tcti_conf))
        else:
            rc = _DLL.botan_tpm2_ctx_init(byref(obj), _ctype_str(tcti_name_maybe_with_conf))
        if rc == -40: # 'Not Implemented'
            raise BotanException("TPM2 is not implemented in this build configuration", rc)
        self.rng_ = None
        super().__init__(obj, _DLL.botan_tpm2_ctx_destroy)

    @staticmethod
    def supports_botan_crypto_backend() -> bool:
        """Returns True if the given build supports the Botan-based crypto backend."""
        rc = _DLL.botan_tpm2_supports_crypto_backend()
        return rc == 1

    def enable_botan_crypto_backend(self, rng):
        """Enables the Botan-based crypto backend.
        The passed rng MUST NOT be dependent on the TPM."""
        # By keeping a reference to the passed-in RNG object, we make sure
        # that the underlying object lives at least as long as this context.
        self.rng_ = rng
        _DLL.botan_tpm2_ctx_enable_crypto_backend(self.handle_(), self.rng_.handle_())

class TPM2Session(TPM2Object):
    """Basic TPM 2.0 Session object, typically users will instantiate a derived class."""

    def __init__(self, obj: c_void_p):
        super().__init__(obj, _DLL.botan_tpm2_session_destroy)

    @staticmethod
    def session_bundle_(*args):
        """Transforms a session bundle passed by the downstream user into a 3-tuple of session handles.
        Users might pass a bare TPM2Session object or an iterable list of such objects."""
        if len(args) == 1:
            if isinstance(args[0], Iterable):
                args = list(args[0])
            elif args[0] is None:
                args = []

        if len(args) <= 3 and all(isinstance(s, TPM2Session) for s in args):
            sessions = list(args)
            while len(sessions) < 3:
                sessions.append(None)
            return (s.handle_() if isinstance(s, TPM2Session) else None for s in sessions)
        else:
            raise BotanException("session bundle arguments must be 0 to 3 TPM2Session objects")


class TPM2UnauthenticatedSession(TPM2Session):
    """Session object that is not bound to any authenication credential.
    It provides basic parameter encryption between the application and the TPM."""
    def __init__(self, ctx: TPM2Context):
        obj = c_void_p(0)
        _DLL.botan_tpm2_unauthenticated_session_init(byref(obj), ctx.handle_())
        super().__init__(obj)

#
# RNG
#
class RandomNumberGenerator:
    # Can also use type "system"
    def __init__(self, rng_type='system', **kwargs):
        """Constructs a RandomNumberGenerator of type rng_type

        Available RNG types are::

        * 'system': Adapter to the operating system's RNG
        * 'user':   Software-PRNG that is auto-seeded by the system RNG
        * 'null':   Mock-RNG that fails if randomness is pulled from it
        * 'hwrng':  Adapter to an available hardware RNG (platform dependent)
        * 'tpm2':   Adapter to a TPM 2.0 RNG
                    (needs additional named arguments tpm2_context= and, optionally, tpm2_sessions=)
        """
        self.__obj = c_void_p(0)
        if rng_type == 'tpm2':
            ctx = kwargs.pop("tpm2_context", None)
            if not ctx or not isinstance(ctx, TPM2Context):
                raise BotanException("Cannot instantiate a TPM2-based RNG without a TPM2 context, pass tpm2_context= argument?")
            sessions = TPM2Session.session_bundle_(kwargs.pop("tpm2_sessions", None))
            if kwargs:
                raise BotanException("Unexpected arguments for TPM2 RNG: %s" % (", ".join(kwargs.keys())))
            _DLL.botan_tpm2_rng_init(byref(self.__obj), ctx.handle_(), *sessions)
        else:
            if kwargs:
                raise BotanException("Unexpected arguments for RNG type %s: %s" % (rng_type, ", ".join(kwargs.keys())))
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
        seedbits = _ctype_bits(seed)
        _DLL.botan_rng_add_entropy(self.__obj, seedbits, len(seedbits))

    def get(self, length):
        out = create_string_buffer(length)
        l = c_size_t(length)
        _DLL.botan_rng_get(self.__obj, out, l)
        return _ctype_bufout(out)

#
# Block cipher
#
class BlockCipher:
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

    def keylength_modulo(self):
        return self.__mod_keylen


#
# Hash function
#
class HashFunction:
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
        bits = _ctype_bits(x)
        _DLL.botan_hash_update(self.__obj, bits, len(bits))

    def final(self):
        out = create_string_buffer(self.output_length())
        _DLL.botan_hash_final(self.__obj, out)
        return _ctype_bufout(out)

#
# Message authentication codes
#
class MsgAuthCode:
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

    def keylength_modulo(self):
        return self.__mod_keylen

    def set_key(self, key):
        _DLL.botan_mac_set_key(self.__obj, key, len(key))

    def set_nonce(self, nonce):
        _DLL.botan_mac_set_nonce(self.__obj, nonce, len(nonce))

    def update(self, x):
        bits = _ctype_bits(x)
        _DLL.botan_mac_update(self.__obj, bits, len(bits))

    def final(self):
        out = create_string_buffer(self.output_length())
        _DLL.botan_mac_final(self.__obj, out)
        return _ctype_bufout(out)

class SymmetricCipher:
    def __init__(self, algo, encrypt=True):
        flags = 0 if encrypt else 1
        self.__obj = c_void_p(0)
        _DLL.botan_cipher_init(byref(self.__obj), _ctype_str(algo), flags)
        self._is_cbc = algo.find('/CBC') > 0
        self._is_encrypt = encrypt

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

    def ideal_update_granularity(self):
        l = c_size_t(0)
        _DLL.botan_cipher_get_ideal_update_granularity(self.__obj, byref(l))
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
        rc = _DLL.botan_cipher_is_authenticated(self.__obj)
        return rc == 1

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
        bits = _ctype_bits(inp)
        inp_sz = c_size_t(len(bits))
        inp_consumed = c_size_t(0)
        extra_bytes = 0
        if final and self._is_encrypt:
            tag_len = self.tag_length()
            if tag_len > 0:
                # AEADs don't expand beyond the tag
                extra_bytes = tag_len
            elif self._is_cbc:
                # Hack: the largest block size currently supported
                extra_bytes = 64
        out = create_string_buffer(inp_sz.value + extra_bytes)
        out_sz = c_size_t(len(out))
        out_written = c_size_t(0)
        flags = c_uint32(1 if final else 0)

        _DLL.botan_cipher_update(self.__obj, flags,
                                 out, out_sz, byref(out_written),
                                 bits, inp_sz, byref(inp_consumed))

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
def pbkdf(algo, password, out_len, iterations=100000, salt=None):
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
    passbits = _ctype_str(password)
    saltbits = _ctype_bits(salt)

    _DLL.botan_pwdhash(_ctype_str("Scrypt"), n, r, p,
                       out_buf, out_len,
                       passbits, len(passbits),
                       saltbits, len(saltbits))

    return out_buf.raw

# Argon2
#
# The variant param should be "Argon2i", "Argon2d", or "Argon2id"
#
# m specifies megabytes of memory used during processing
# t specifies the number of passes
# p specifies the parallelism
#
# returns an output of out_len bytes
def argon2(variant, out_len, password, salt, m=256, t=1, p=1):
    out_buf = create_string_buffer(out_len)
    passbits = _ctype_str(password)
    saltbits = _ctype_bits(salt)

    _DLL.botan_pwdhash(_ctype_str(variant), m, t, p,
                       out_buf, out_len,
                       passbits, len(passbits),
                       saltbits, len(saltbits))

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
class PublicKey: # pylint: disable=invalid-name
    def __init__(self, obj=None):
        if not obj:
            obj = c_void_p(0)
        self.__obj = obj

    @classmethod
    def load(cls, val):
        pub = PublicKey()
        bits = _ctype_bits(val)
        _DLL.botan_pubkey_load(byref(pub.handle_()), bits, len(bits))
        return pub

    @classmethod
    def load_rsa(cls, n, e):
        pub = PublicKey()
        n = MPI(n)
        e = MPI(e)
        _DLL.botan_pubkey_load_rsa(byref(pub.handle_()), n.handle_(), e.handle_())
        return pub

    @classmethod
    def load_dsa(cls, p, q, g, y):
        pub = PublicKey()
        p = MPI(p)
        q = MPI(q)
        g = MPI(g)
        y = MPI(y)
        _DLL.botan_pubkey_load_dsa(byref(pub.handle_()), p.handle_(), q.handle_(), g.handle_(), y.handle_())
        return pub

    @classmethod
    def load_dh(cls, p, g, y):
        pub = PublicKey()
        p = MPI(p)
        g = MPI(g)
        y = MPI(y)
        _DLL.botan_pubkey_load_dh(byref(pub.handle_()), p.handle_(), g.handle_(), y.handle_())
        return pub

    @classmethod
    def load_elgamal(cls, p, q, g, y):
        pub = PublicKey()
        p = MPI(p)
        q = MPI(q)
        g = MPI(g)
        y = MPI(y)
        _DLL.botan_pubkey_load_elgamal(byref(pub.handle_()), p.handle_(), q.handle_(), g.handle_(), y.handle_())
        return pub

    @classmethod
    def load_ecdsa(cls, curve, pub_x, pub_y):
        pub = PublicKey()
        pub_x = MPI(pub_x)
        pub_y = MPI(pub_y)
        _DLL.botan_pubkey_load_ecdsa(byref(pub.handle_()), pub_x.handle_(), pub_y.handle_(), _ctype_str(curve))
        return pub

    @classmethod
    def load_ecdh(cls, curve, pub_x, pub_y):
        pub = PublicKey()
        pub_x = MPI(pub_x)
        pub_y = MPI(pub_y)
        _DLL.botan_pubkey_load_ecdh(byref(pub.handle_()), pub_x.handle_(), pub_y.handle_(), _ctype_str(curve))
        return pub

    @classmethod
    def load_sm2(cls, curve, pub_x, pub_y):
        pub = PublicKey()
        pub_x = MPI(pub_x)
        pub_y = MPI(pub_y)
        _DLL.botan_pubkey_load_sm2(byref(pub.handle_()), pub_x.handle_(), pub_y.handle_(), _ctype_str(curve))
        return pub

    @classmethod
    def load_kyber(cls, key):
        pub = PublicKey()
        _DLL.botan_pubkey_load_kyber(byref(pub.handle_()), key, len(key))
        return pub

    @classmethod
    def load_ml_kem(cls, mlkem_mode, key):
        pub = PublicKey()
        _DLL.botan_pubkey_load_ml_kem(byref(pub.handle_()), key, len(key), _ctype_str(mlkem_mode))
        return pub

    @classmethod
    def load_ml_dsa(cls, mldsa_mode, key):
        pub = PublicKey()
        _DLL.botan_pubkey_load_ml_dsa(byref(pub.handle_()), key, len(key), _ctype_str(mldsa_mode))
        return pub

    @classmethod
    def load_slh_dsa(cls, slhdsa_mode, key):
        pub = PublicKey()
        _DLL.botan_pubkey_load_slh_dsa(byref(pub.handle_()), key, len(key), _ctype_str(slhdsa_mode))
        return pub

    @classmethod
    def load_frodokem(cls, frodo_mode, key):
        pub = PublicKey()
        _DLL.botan_pubkey_load_frodokem(byref(pub.handle_()), key, len(key), _ctype_str(frodo_mode))
        return pub

    @classmethod
    def load_classic_mceliece(cls, cmce_mode, key):
        pub = PublicKey()
        _DLL.botan_pubkey_load_classic_mceliece(byref(pub.handle_()), key, len(key), _ctype_str(cmce_mode))
        return pub

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
            return self.to_pem()
        else:
            return self.to_der()

    def to_der(self):
        return _call_fn_viewing_vec(lambda vc, vfn: _DLL.botan_pubkey_view_der(self.__obj, vc, vfn))

    def to_pem(self):
        return _call_fn_viewing_str(lambda vc, vfn: _DLL.botan_pubkey_view_pem(self.__obj, vc, vfn))

    def to_raw(self):
        return _call_fn_viewing_vec(lambda vc, vfn: _DLL.botan_pubkey_view_raw(self.__obj, vc, vfn))

    def view_kyber_raw_key(self):
        """Deprecated: use to_raw() instead"""
        return _call_fn_viewing_vec(lambda vc, vfn: _DLL.botan_pubkey_view_kyber_raw_key(self.__obj, vc, vfn))

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

    def object_identifier(self):
        oid = OID()
        _DLL.botan_pubkey_oid(byref(oid.handle_()), self.__obj)
        return oid

    def get_public_point(self):
        return _call_fn_viewing_vec(lambda vc, vfn: _DLL.botan_pubkey_view_ec_public_point(self.__obj, vc, vfn))

#
# Private Key
#
class PrivateKey:
    def __init__(self, obj=None):
        if not obj:
            obj = c_void_p(0)
        self.__obj = obj

    @classmethod
    def load(cls, val, passphrase=""):
        priv = PrivateKey()
        rng_obj = c_void_p(0) # unused in recent versions
        bits = _ctype_bits(val)
        _DLL.botan_privkey_load(byref(priv.handle_()), rng_obj, bits, len(bits), _ctype_str(passphrase))
        return priv

    @classmethod
    def create(cls, algo, params, rng_obj):
        if algo == 'rsa':
            algo = 'RSA'
            params = "%d" % (params)
        elif algo == 'ecdsa':
            algo = 'ECDSA'
        elif algo in ['ecdh', 'ECDH']:
            if params in ['x25519', 'curve25519']:
                algo = 'X25519'
                params = ''
            elif params == 'x448':
                algo = 'X448'
                params = ''
            else:
                algo = 'ECDH'
        elif algo in ['mce', 'mceliece']:
            algo = 'McEliece'
            params = "%d,%d" % (params[0], params[1])

        priv = PrivateKey()
        _DLL.botan_privkey_create(byref(priv.handle_()), _ctype_str(algo), _ctype_str(params), rng_obj.handle_())
        return priv

    @classmethod
    def create_ec(cls, algo, ec_group, rng_obj):
        obj = c_void_p(0)
        _DLL.botan_ec_privkey_create(byref(obj), _ctype_str(algo), ec_group.handle_(), rng_obj.handle_())
        return PrivateKey(obj)

    @classmethod
    def load_rsa(cls, p, q, e):
        priv = PrivateKey()
        p = MPI(p)
        q = MPI(q)
        e = MPI(e)
        _DLL.botan_privkey_load_rsa(byref(priv.handle_()), p.handle_(), q.handle_(), e.handle_())
        return priv

    @classmethod
    def load_dsa(cls, p, q, g, x):
        priv = PrivateKey()
        p = MPI(p)
        q = MPI(q)
        g = MPI(g)
        x = MPI(x)
        _DLL.botan_privkey_load_dsa(byref(priv.handle_()), p.handle_(), q.handle_(), g.handle_(), x.handle_())
        return priv

    @classmethod
    def load_dh(cls, p, g, x):
        priv = PrivateKey()
        p = MPI(p)
        g = MPI(g)
        x = MPI(x)
        _DLL.botan_privkey_load_dh(byref(priv.handle_()), p.handle_(), g.handle_(), x.handle_())
        return priv

    @classmethod
    def load_elgamal(cls, p, q, g, x):
        priv = PrivateKey()
        p = MPI(p)
        q = MPI(q)
        g = MPI(g)
        x = MPI(x)
        _DLL.botan_privkey_load_elgamal(byref(priv.handle_()), p.handle_(), q.handle_(), g.handle_(), x.handle_())
        return priv

    @classmethod
    def load_ecdsa(cls, curve, x):
        priv = PrivateKey()
        x = MPI(x)
        _DLL.botan_privkey_load_ecdsa(byref(priv.handle_()), x.handle_(), _ctype_str(curve))
        return priv

    @classmethod
    def load_ecdh(cls, curve, x):
        priv = PrivateKey()
        x = MPI(x)
        _DLL.botan_privkey_load_ecdh(byref(priv.handle_()), x.handle_(), _ctype_str(curve))
        return priv

    @classmethod
    def load_sm2(cls, curve, x):
        priv = PrivateKey()
        x = MPI(x)
        _DLL.botan_privkey_load_sm2(byref(priv.handle_()), x.handle_(), _ctype_str(curve))
        return priv

    @classmethod
    def load_kyber(cls, key):
        priv = PrivateKey()
        _DLL.botan_privkey_load_kyber(byref(priv.handle_()), key, len(key))
        return priv

    @classmethod
    def load_ml_kem(cls, mlkem_mode, key):
        priv = PrivateKey()
        _DLL.botan_privkey_load_ml_kem(byref(priv.handle_()), key, len(key), _ctype_str(mlkem_mode))
        return priv

    @classmethod
    def load_ml_dsa(cls, mldsa_mode, key):
        priv = PrivateKey()
        _DLL.botan_privkey_load_ml_dsa(byref(priv.handle_()), key, len(key), _ctype_str(mldsa_mode))
        return priv

    @classmethod
    def load_slh_dsa(cls, slh_dsa, key):
        priv = PrivateKey()
        _DLL.botan_privkey_load_slh_dsa(byref(priv.handle_()), key, len(key), _ctype_str(slh_dsa))
        return priv

    @classmethod
    def load_frodokem(cls, frodo_mode, key):
        priv = PrivateKey()
        _DLL.botan_privkey_load_frodokem(byref(priv.handle_()), key, len(key), _ctype_str(frodo_mode))
        return priv

    @classmethod
    def load_classic_mceliece(cls, cmce_mode, key):
        priv = PrivateKey()
        _DLL.botan_privkey_load_classic_mceliece(byref(priv.handle_()), key, len(key), _ctype_str(cmce_mode))
        return priv

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
        pub = PublicKey()
        _DLL.botan_privkey_export_pubkey(byref(pub.handle_()), self.__obj)
        return pub

    def to_der(self):
        return _call_fn_viewing_vec(lambda vc, vfn: _DLL.botan_privkey_view_der(self.__obj, vc, vfn))

    def to_pem(self):
        return _call_fn_viewing_str(lambda vc, vfn: _DLL.botan_privkey_view_pem(self.__obj, vc, vfn))

    def to_raw(self):
        return _call_fn_viewing_vec(lambda vc, vfn: _DLL.botan_privkey_view_raw(self.__obj, vc, vfn))

    def view_kyber_raw_key(self):
        """Deprecated: use to_raw() instead"""
        return _call_fn_viewing_vec(lambda vc, vfn: _DLL.botan_privkey_view_kyber_raw_key(self.__obj, vc, vfn))

    def export(self, pem=False):
        if pem:
            return self.to_pem()
        else:
            return self.to_der()

    def export_encrypted(self, passphrase, rng, pem=False, msec=300, cipher=None, pbkdf=None): # pylint: disable=redefined-outer-name
        if pem:
            return _call_fn_viewing_str(
                lambda vc, vfn: _DLL.botan_privkey_view_encrypted_pem_timed(
                    self.__obj, rng.handle_(), _ctype_str(passphrase),
                    _ctype_str(cipher), _ctype_str(pbkdf), c_size_t(msec), vc, vfn))
        else:
            return _call_fn_viewing_vec(
                lambda vc, vfn: _DLL.botan_privkey_view_encrypted_der_timed(
                    self.__obj, rng.handle_(), _ctype_str(passphrase),
                    _ctype_str(cipher), _ctype_str(pbkdf), c_size_t(msec), vc, vfn))

    def get_field(self, field_name):
        v = MPI()
        _DLL.botan_privkey_get_field(v.handle_(), self.__obj, _ctype_str(field_name))
        return int(v)

    def object_identifier(self):
        oid = OID()
        _DLL.botan_privkey_oid(byref(oid.handle_()), self.__obj)
        return oid

    def stateful_operation(self):
        r = c_int(0)
        _DLL.botan_privkey_stateful_operation(self.__obj, byref(r))
        if r.value == 0:
            return False
        return True

    def remaining_operations(self):
        r = c_uint64(0)
        _DLL.botan_privkey_remaining_operations(self.__obj, byref(r))
        return r.value

class PKEncrypt:
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


class PKDecrypt:
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
        bits = _ctype_bits(msg)
        _DLL.botan_pk_op_decrypt(self.__obj, outbuf, byref(outbuf_sz), bits, len(bits))
        return outbuf.raw[0:int(outbuf_sz.value)]

class PKSign: # pylint: disable=invalid-name
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

class PKVerify:
    def __init__(self, key, padding, der=False):
        self.__obj = c_void_p(0)
        flags = c_uint32(1) if der else c_uint32(0)
        _DLL.botan_pk_op_verify_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        _DLL.botan_pk_op_verify_destroy(self.__obj)

    def update(self, msg):
        bits = _ctype_bits(msg)
        _DLL.botan_pk_op_verify_update(self.__obj, bits, len(bits))

    def check_signature(self, signature):
        bits = _ctype_bits(signature)
        rc = _DLL.botan_pk_op_verify_finish(self.__obj, bits, len(bits))
        if rc == 0:
            return True
        return False

class PKKeyAgreement:
    def __init__(self, key, kdf_name):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        _DLL.botan_pk_op_key_agreement_create(byref(self.__obj), key.handle_(), _ctype_str(kdf_name), flags)

        self.m_public_value = _call_fn_viewing_vec(
            lambda vc, vfn: _DLL.botan_pk_op_key_agreement_view_public(key.handle_(), vc, vfn))

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

class KemEncrypt:
    def __init__(self, key, params):
        self.__obj = c_void_p(0)
        _DLL.botan_pk_op_kem_encrypt_create(byref(self.__obj), key.handle_(), _ctype_str(params))

    def __del__(self):
        _DLL.botan_pk_op_kem_encrypt_destroy(self.__obj)

    def shared_key_length(self, desired_key_len):
        return _call_fn_returning_sz(
            lambda l: _DLL.botan_pk_op_kem_encrypt_shared_key_length(self.__obj, desired_key_len, l))

    def encapsulated_key_length(self):
        return _call_fn_returning_sz(
            lambda l: _DLL.botan_pk_op_kem_encrypt_encapsulated_key_length(self.__obj, l))

    def create_shared_key(self, rng, salt, desired_key_len):
        shared_key_len = self.shared_key_length(desired_key_len)
        shared_key_buf = create_string_buffer(shared_key_len)

        encapsulated_key_len = self.encapsulated_key_length()
        encapsulated_key_buf = create_string_buffer(encapsulated_key_len)

        _DLL.botan_pk_op_kem_encrypt_create_shared_key(
            self.__obj,
            rng.handle_(),
            salt,
            len(salt),
            c_size_t(desired_key_len),
            shared_key_buf,
            c_size_t(shared_key_len),
            encapsulated_key_buf,
            c_size_t(encapsulated_key_len)
        )

        shared_key = shared_key_buf.raw[:]
        encapsulated_key = encapsulated_key_buf.raw[:]

        return (shared_key, encapsulated_key)

class KemDecrypt:
    def __init__(self, key, params):
        self.__obj = c_void_p(0)
        _DLL.botan_pk_op_kem_decrypt_create(byref(self.__obj), key.handle_(), _ctype_str(params))

    def __del__(self):
        _DLL.botan_pk_op_kem_decrypt_destroy(self.__obj)

    def shared_key_length(self, desired_key_len):
        return _call_fn_returning_sz(
            lambda l: _DLL.botan_pk_op_kem_decrypt_shared_key_length(self.__obj, desired_key_len, l))

    def decrypt_shared_key(self, salt, desired_key_len, encapsulated_key):
        shared_key_len = self.shared_key_length(desired_key_len)

        return _call_fn_returning_vec(
            shared_key_len,
            lambda b, bl: _DLL.botan_pk_op_kem_decrypt_shared_key(
                self.__obj,
                salt,
                len(salt),
                encapsulated_key,
                c_size_t(len(encapsulated_key)),
                c_size_t(desired_key_len),
                b,
                bl)
        )

def _load_buf_or_file(filename, buf, file_fn, buf_fn):
    if filename is None and buf is None:
        raise BotanException("No filename or buf given")
    if filename is not None and buf is not None:
        raise BotanException("Both filename and buf given")

    obj = c_void_p(0)

    if filename is not None:
        file_fn(byref(obj), _ctype_str(filename))
    elif buf is not None:
        bits = _ctype_bits(buf)
        buf_fn(byref(obj), bits, len(bits))

    return obj


#
# X.509 certificates
#
class X509CertificateBuilder:
    def __init__(self, opts, expire_time=None):
        self.__obj = c_void_p(0)
        _DLL.botan_x509_create_cert_params_builder(byref(self.__obj), _ctype_str(opts), c_uint32(expire_time) if expire_time else None)

    def __del__(self):
        _DLL.botan_x509_cert_params_builder_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def add_common_name(self, name):
        _DLL.botan_x509_cert_params_builder_add_common_name(self.__obj, _ctype_str(name))

    def add_country(self, country):
        _DLL.botan_x509_cert_params_builder_add_country(self.__obj, _ctype_str(country))

    def add_organization(self, organization):
        _DLL.botan_x509_cert_params_builder_add_organization(self.__obj, _ctype_str(organization))

    def add_org_unit(self, org_unit):
        _DLL.botan_x509_cert_params_builder_add_org_unit(self.__obj, _ctype_str(org_unit))

    def add_locality(self, locality):
        _DLL.botan_x509_cert_params_builder_add_locality(self.__obj, _ctype_str(locality))

    def add_state(self, state):
        _DLL.botan_x509_cert_params_builder_add_state(self.__obj, _ctype_str(state))

    def add_serial_number(self, serial_number):
        _DLL.botan_x509_cert_params_builder_add_serial_number(self.__obj, _ctype_str(serial_number))

    def add_email(self, email):
        _DLL.botan_x509_cert_params_builder_add_email(self.__obj, _ctype_str(email))

    def add_uri(self, uri):
        _DLL.botan_x509_cert_params_builder_add_uri(self.__obj, _ctype_str(uri))

    def add_ip(self, ip):
        _DLL.botan_x509_cert_params_builder_add_ip(self.__obj, _ctype_str(ip))

    def add_dns(self, dns):
        _DLL.botan_x509_cert_params_builder_add_dns(self.__obj, _ctype_str(dns))

    def add_xmpp(self, xmpp):
        _DLL.botan_x509_cert_params_builder_add_xmpp(self.__obj, _ctype_str(xmpp))

    def add_challenge(self, challenge):
        _DLL.botan_x509_cert_params_builder_add_challenge(self.__obj, _ctype_str(challenge))

    def mark_as_ca_key(self, limit):
        _DLL.botan_x509_cert_params_builder_mark_as_ca_key(self.__obj, c_size_t(limit))

    def add_not_before(self, time_since_epoch):
        _DLL.botan_x509_cert_params_builder_add_not_before(self.__obj, time_since_epoch)

    def add_not_after(self, time_since_epoch):
        _DLL.botan_x509_cert_params_builder_add_not_after(self.__obj, time_since_epoch)

    def add_constraints(self, usage_list):
        # TODO this sucks, where enum
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
                pass
            usage += usage_values[u]
        _DLL.botan_x509_cert_params_builder_add_constraints(self.__obj, c_uint32(usage))

    def add_ex_constraints(self, oid):
        _DLL.botan_x509_cert_params_builder_add_ex_constraint(self.__obj, oid.handle_())

    def add_ext_ip_addr_blocks(self, ip_addr_blocks):
        _DLL.botan_x509_cert_params_builder_add_ext_ip_addr_blocks(self.__obj, ip_addr_blocks.handle_())

    def add_ext_as_blocks(self, as_blocks):
        _DLL.botan_x509_cert_params_builder_add_ext_as_blocks(self.__obj, as_blocks.handle_())

    def create_req(self, key, hash_fn, rng):
        req = PKCS10Req()
        _DLL.botan_x509_create_pkcs10_req(byref(req.handle_()), self.__obj, key.handle_(), _ctype_str(hash_fn), rng.handle_())
        return req


class X509ExtIPAddrBlocks:
    def __init__(self, cert=None):
        self.__obj = c_void_p(0)
        if cert:
            _DLL.botan_x509_ext_create_ip_addr_blocks_from_cert(byref(self.__obj), cert.handle_())
        else:
            _DLL.botan_x509_ext_create_ip_addr_blocks(byref(self.__obj))

    def __del__(self):
        _DLL.botan_x509_ext_ip_addr_blocks_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def add_addr(self, ip, safi=None):
        self.add_range(ip, ip, safi)

    def add_range(self, min_, max_, safi=None):
        min_len = len(min_)
        if min_len not in (4, 16) or len(max_) != min_len:
            raise BotanException("Address must be 4 or 16 bytes long")

        ipv6 = 1 if min_len == 16 else 0
        safi = byref(c_uint8(safi)) if safi is not None else None
        _DLL.botan_x509_ext_ip_addr_blocks_add_ip_addr(self.__obj, bytes(min_), bytes(max_), c_int(ipv6), safi)

    def restrict(self, ipv6, safi=None):
        ipv6 = 1 if ipv6 else 0
        safi = byref(c_uint8(safi)) if safi is not None else None
        _DLL.botan_x509_ext_ip_addr_blocks_restrict(self.__obj, c_int(ipv6), safi)

    def inherit(self, ipv6, safi=None):
        ipv6 = 1 if ipv6 else 0
        safi = byref(c_uint8(safi)) if safi is not None else None
        _DLL.botan_x509_ext_ip_addr_blocks_inherit(self.__obj, c_int(ipv6), safi)

    def addresses(self):
        v4 = []
        v6 = []

        v4_count = c_size_t(0)
        v6_count = c_size_t(0)

        _DLL.botan_x509_ext_ip_addr_blocks_get_counts(self.__obj, byref(v4_count), byref(v6_count))

        v4_count = v4_count.value
        v6_count = v6_count.value

        for (ipv6, start, stop) in ((0, 0, v4_count), (1, v4_count, v4_count + v6_count)):
            for i in range(start, stop):
                size = 16 if ipv6 else 4

                has_safi = c_int(0)
                safi = c_uint8(0)
                present = c_int(0)
                count = c_size_t(0)
                _DLL.botan_x509_ext_ip_addr_blocks_get_family(self.__obj, c_int(ipv6), c_size_t(i), byref(has_safi), byref(safi), byref(present), byref(count))
                ranges = None
                if present.value == 1:
                    ranges = []
                    for entry in range(count.value):
                        min_, max_ = _call_fn_returning_vec_pair(
                            size, size, lambda mi, _, ma, l, ipv6=ipv6, i=i, entry=entry: _DLL.botan_x509_ext_ip_addr_blocks_get_address(
                                self.__obj,
                                c_int(ipv6),
                                c_size_t(i),
                                c_size_t(entry),
                                mi,
                                ma,
                                l))
                        ranges.append((tuple(min_), tuple(max_)))

                safi = safi.value if has_safi.value == 1 else None
                ranges = ranges if ranges is not None else None
                if ipv6 == 0:
                    v4.append((safi, ranges))
                else:
                    v6.append((safi, ranges))

        return (v4, v6)


class X509ExtASBlocks:
    def __init__(self, cert=None):
        self.__obj = c_void_p(0)
        if cert:
            _DLL.botan_x509_ext_create_as_blocks_from_cert(byref(self.__obj), cert.handle_())
        else:
            _DLL.botan_x509_ext_create_as_blocks(byref(self.__obj))

    def __del__(self):
        _DLL.botan_x509_ext_as_blocks_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def add_asnum(self, asnum):
        self.add_asnum_range(asnum, asnum)

    def add_asnum_range(self, min_, max_):
        _DLL.botan_x509_ext_as_blocks_add_asnum(self.__obj, c_uint32(min_), c_uint32(max_))

    def restrict_asnum(self):
        _DLL.botan_x509_ext_as_blocks_restrict_asnum(self.__obj)

    def inherit_asnum(self):
        _DLL.botan_x509_ext_as_blocks_inherit_asnum(self.__obj)

    def add_rdi(self, rdi):
        self.add_rdi_range(rdi, rdi)

    def add_rdi_range(self, min_, max_):
        _DLL.botan_x509_ext_as_blocks_add_rdi(self.__obj, c_uint32(min_), c_uint32(max_))

    def restrict_rdi(self):
        _DLL.botan_x509_ext_as_blocks_restrict_rdi(self.__obj)

    def inherit_rdi(self):
        _DLL.botan_x509_ext_as_blocks_inherit_rdi(self.__obj)

    def asnum(self):
        present = c_int(0)
        count = c_size_t(0)
        _DLL.botan_x509_ext_as_blocks_get_asnum(self.__obj, byref(present), byref(count))

        # asnum is 'inherit'
        if present.value == 0:
            return None

        asnums = []
        for i in range(count.value):
            min_ = c_uint32(0)
            max_ = c_uint32(0)
            _DLL.botan_x509_ext_as_blocks_get_asnum_at(self.__obj, c_size_t(i), byref(min_), byref(max_))
            asnums.append((min_.value, max_.value))
        return asnums

    def rdi(self):
        present = c_int(0)
        count = c_size_t(0)
        _DLL.botan_x509_ext_as_blocks_get_rdi(self.__obj, byref(present), byref(count))

        # rdi is 'inherit'
        if present.value == 0:
            return None

        rdis = []
        for i in range(count.value):
            min_ = c_uint32(0)
            max_ = c_uint32(0)
            _DLL.botan_x509_ext_as_blocks_get_rdi_at(self.__obj, c_size_t(i), byref(min_), byref(max_))
            rdis.append((min_.value, max_.value))
        return rdis


class PKCS10Req:
    def __init__(self):
        self.__obj = c_void_p(0)

    def __del__(self):
        _DLL.botan_x509_pkcs10_req_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def sign(self, issuing_cert, issuing_key, rng, not_before, not_after, hash_fn, padding):
        cert = X509Cert()
        _DLL.botan_x509_sign_req(
            byref(cert.handle_()),
            self.__obj,
            issuing_cert.handle_(),
            issuing_key.handle_(),
            rng.handle_(),
            not_before,
            not_after,
            _ctype_str(hash_fn),
            _ctype_str(padding)
        )
        return cert

    def to_pem(self):
        return _call_fn_viewing_str(lambda vc, vfn: _DLL.botan_x509_pkcs10_req_view_pem(self.__obj, vc, vfn))


class X509Cert: # pylint: disable=invalid-name
    def __init__(self, filename=None, buf=None):
        if not filename and not buf:
            self.__obj = c_void_p(0)
        else:
            self.__obj = _load_buf_or_file(filename, buf, _DLL.botan_x509_cert_load_file, _DLL.botan_x509_cert_load)

    def __del__(self):
        _DLL.botan_x509_cert_destroy(self.__obj)

    @classmethod
    def create_self_signed(cls, key, opts, hash_fn, padding, rng):
        cert = X509Cert()
        _DLL.botan_x509_create_self_signed_cert(byref(cert.handle_()), key.handle_(), opts.handle_(), _ctype_str(hash_fn), _ctype_str(padding), rng.handle_())
        return cert

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
        return _call_fn_viewing_str(
            lambda vc, vfn: _DLL.botan_x509_cert_view_as_string(self.__obj, vc, vfn))

    def to_pem(self):
        return _call_fn_viewing_str(
            lambda vc, vfn: _DLL.botan_x509_cert_view_pem(self.__obj, vc, vfn))

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
        return _call_fn_viewing_vec(
            lambda vc, vfn: _DLL.botan_x509_cert_view_public_key_bits(self.__obj, vc, vfn))

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

    def key_constraints(self):
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
        usage = c_uint32(0)
        _DLL.botan_x509_get_key_constraints(self.__obj, byref(usage))
        if usage.value == 0:
            return ["NO_CONSTRAINTS"]
        else:
            return [name for name, bit in usage_values.items() if bit != 0 and usage.value & bit]

    def is_ca(self):
        is_ca = c_int(0)
        limit = c_size_t(0)
        _DLL.botan_x509_get_basic_constraints(self.__obj, byref(is_ca), byref(limit))
        if is_ca.value == 0:
            return (False, 0)
        else:
            return (True, limit.value)

    def ocsp_responder(self):
        return _call_fn_viewing_str(
            lambda vc, vfn: _DLL.botan_x509_get_ocsp_responder(self.__obj, vc, vfn))

    def is_self_signed(self):
        self_signed = c_int(0)
        _DLL.botan_x509_is_self_signed(self.__obj, byref(self_signed))
        if self_signed.value == 0:
            return False
        else:
            return True

    def ext_ip_addr_blocks(self):
        return X509ExtIPAddrBlocks(self)

    def ext_as_blocks(self):
        return X509ExtASBlocks(self)

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
class X509CRL:
    def __init__(self, filename=None, buf=None):
        self.__obj = c_void_p(0)
        self.__obj = _load_buf_or_file(filename, buf, _DLL.botan_x509_crl_load_file, _DLL.botan_x509_crl_load)

    def __del__(self):
        _DLL.botan_x509_crl_destroy(self.__obj)

    def handle_(self):
        return self.__obj


class MPI:

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
        out = create_string_buffer(2*self.byte_count() + 3)
        _DLL.botan_mp_to_hex(self.__obj, out)
        return int(out.value, 16)

    def __repr__(self):
        # Should have a better size estimate than this ...
        bits = self.bit_count()
        est_digits = 4 if bits < 3 else bits
        out_len = c_size_t(est_digits)
        out = create_string_buffer(out_len.value)

        _DLL.botan_mp_to_str(self.__obj, c_uint8(10), out, byref(out_len))

        out = out.raw[0:int(out_len.value - 1)]
        return _ctype_to_str(out)

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


class OID:
    def __init__(self, obj=None):
        if not obj:
            obj = c_void_p(0)
        self.__obj = obj

    def __del__(self):
        _DLL.botan_oid_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    @classmethod
    def from_string(cls, value):
        oid = OID()
        _DLL.botan_oid_from_string(byref(oid.handle_()), _ctype_str(value))
        return oid

    def to_string(self):
        return _call_fn_viewing_str(lambda vc, vfn: _DLL.botan_oid_view_string(self.__obj, vc, vfn))

    def to_name(self):
        return _call_fn_viewing_str(lambda vc, vfn: _DLL.botan_oid_view_name(self.__obj, vc, vfn))

    def register(self, name):
        _DLL.botan_oid_register(self.__obj, _ctype_str(name))

    def cmp(self, other):
        r = c_int(0)
        _DLL.botan_oid_cmp(byref(r), self.__obj, other.handle_())
        return r.value

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


class ECGroup:
    def __init__(self, obj=None):
        if not obj:
            obj = c_void_p(0)
        self.__obj = obj

    def handle_(self):
        return self.__obj

    def __del__(self):
        _DLL.botan_ec_group_destroy(self.__obj)

    @classmethod
    def supports_application_specific_group(cls):
        r = c_int(0)
        _DLL.botan_ec_group_supports_application_specific_group(byref(r))
        if r.value == 0:
            return False
        return True

    @classmethod
    def supports_named_group(cls, name):
        r = c_int(0)
        _DLL.botan_ec_group_supports_named_group(_ctype_str(name), byref(r))
        if r.value == 0:
            return False
        return True

    @classmethod
    def from_params(cls, oid, p, a, b, base_x, base_y, order):
        ec_group = ECGroup()
        _DLL.botan_ec_group_from_params(
            byref(ec_group.handle_()),
            oid.handle_(),
            p.handle_(),
            a.handle_(),
            b.handle_(),
            base_x.handle_(),
            base_y.handle_(),
            order.handle_()
        )
        return ec_group

    @classmethod
    def from_ber(cls, ber):
        ec_group = ECGroup()
        _DLL.botan_ec_group_from_ber(byref(ec_group.handle_()), ber, len(ber))
        return ec_group

    @classmethod
    def from_pem(cls, pem):
        ec_group = ECGroup()
        _DLL.botan_ec_group_from_pem(byref(ec_group.handle_()), _ctype_str(pem))
        return ec_group

    @classmethod
    def from_oid(cls, oid):
        ec_group = ECGroup()
        _DLL.botan_ec_group_from_oid(byref(ec_group.handle_()), oid.handle_())
        return ec_group

    @classmethod
    def from_name(cls, name):
        ec_group = ECGroup()
        _DLL.botan_ec_group_from_name(byref(ec_group.handle_()), _ctype_str(name))
        return ec_group

    def to_der(self):
        return _call_fn_viewing_vec(lambda vc, vfn: _DLL.botan_ec_group_view_der(self.__obj, vc, vfn))

    def to_pem(self):
        return _call_fn_viewing_str(lambda vc, vfn: _DLL.botan_ec_group_view_pem(self.__obj, vc, vfn))

    def get_curve_oid(self):
        oid = OID()
        _DLL.botan_ec_group_get_curve_oid(byref(oid.handle_()), self.__obj)
        return oid

    def get_p(self):
        p = MPI()
        _DLL.botan_ec_group_get_p(byref(p.handle_()), self.__obj)
        return p

    def get_a(self):
        a = MPI()
        _DLL.botan_ec_group_get_a(byref(a.handle_()), self.__obj)
        return a

    def get_b(self):
        b = MPI()
        _DLL.botan_ec_group_get_b(byref(b.handle_()), self.__obj)
        return b

    def get_g_x(self):
        g_x = MPI()
        _DLL.botan_ec_group_get_g_x(byref(g_x.handle_()), self.__obj)
        return g_x

    def get_g_y(self):
        g_y = MPI()
        _DLL.botan_ec_group_get_g_y(byref(g_y.handle_()), self.__obj)
        return g_y

    def get_order(self):
        order = MPI()
        _DLL.botan_ec_group_get_order(byref(order.handle_()), self.__obj)
        return order

    def __eq__(self, other):
        rc = _DLL.botan_ec_group_equal(self.__obj, other.handle_())
        return rc == 1

    def __ne__(self, other):
        return not self == other


class FormatPreservingEncryptionFE1:

    def __init__(self, modulus, key, rounds=5, compat_mode=False):
        flags = c_uint32(1 if compat_mode else 0)
        self.__obj = c_void_p(0)
        _DLL.botan_fpe_fe1_init(byref(self.__obj), modulus.handle_(), key, len(key), c_size_t(rounds), flags)

    def __del__(self):
        _DLL.botan_fpe_destroy(self.__obj)

    def encrypt(self, msg, tweak):
        r = MPI(msg)
        bits = _ctype_bits(tweak)
        _DLL.botan_fpe_encrypt(self.__obj, r.handle_(), bits, len(bits))
        return r

    def decrypt(self, msg, tweak):
        r = MPI(msg)
        bits = _ctype_bits(tweak)
        _DLL.botan_fpe_decrypt(self.__obj, r.handle_(), bits, len(bits))
        return r

class HOTP:
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

class TOTP:
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

def nist_key_wrap(kek, key, cipher=None):
    cipher_algo = "AES-%d" % (8*len(kek)) if cipher is None else cipher
    padding = 0
    output = create_string_buffer(len(key) + 8)
    out_len = c_size_t(len(output))
    _DLL.botan_nist_kw_enc(_ctype_str(cipher_algo), padding,
                           key, len(key),
                           kek, len(kek),
                           output, byref(out_len))
    return output[0:int(out_len.value)]

def nist_key_unwrap(kek, wrapped, cipher=None):
    cipher_algo = "AES-%d" % (8*len(kek)) if cipher is None else cipher
    padding = 0
    output = create_string_buffer(len(wrapped))
    out_len = c_size_t(len(output))
    _DLL.botan_nist_kw_dec(_ctype_str(cipher_algo), padding,
                           wrapped, len(wrapped),
                           kek, len(kek),
                           output, byref(out_len))
    return output[0:int(out_len.value)]

class Srp6ServerSession:
    __obj = c_void_p(0)

    def __init__(self, group):
        _DLL.botan_srp6_server_session_init(byref(self.__obj))
        self.__group = group
        self.__group_size = _call_fn_returning_sz(
            lambda l: _DLL.botan_srp6_group_size(_ctype_str(group), l))

    def __del__(self):
        _DLL.botan_srp6_server_session_destroy(self.__obj)

    def step1(self, verifier, hsh, rng):
        return _call_fn_returning_vec(self.__group_size,
                                      lambda b, bl:
                                      _DLL.botan_srp6_server_session_step1(self.__obj,
                                                                           verifier, len(verifier),
                                                                           _ctype_str(self.__group),
                                                                           _ctype_str(hsh),
                                                                           rng.handle_(),
                                                                           b, bl))

    def step2(self, a):
        return _call_fn_returning_vec(self.__group_size, lambda k, kl:
                                      _DLL.botan_srp6_server_session_step2(self.__obj,
                                                                           a, len(a),
                                                                           k, kl))

def srp6_generate_verifier(identifier, password, salt, group, hsh):
    sz = _call_fn_returning_sz(lambda l: _DLL.botan_srp6_group_size(_ctype_str(group), l))

    return _call_fn_returning_vec(sz, lambda v, vl:
                                  _DLL.botan_srp6_generate_verifier(_ctype_str(identifier),
                                                                    _ctype_str(password),
                                                                    salt, len(salt),
                                                                    _ctype_str(group),
                                                                    _ctype_str(hsh),
                                                                    v, vl))

def srp6_client_agree(username, password, group, hsh, salt, b, rng):
    sz = _call_fn_returning_sz(lambda l: _DLL.botan_srp6_group_size(_ctype_str(group), l))

    return _call_fn_returning_vec_pair(sz, sz, lambda a, al, k, kl:
                                       _DLL.botan_srp6_client_agree(_ctype_str(username),
                                                                    _ctype_str(password),
                                                                    _ctype_str(group),
                                                                    _ctype_str(hsh),
                                                                    salt, len(salt),
                                                                    b, len(b),
                                                                    rng.handle_(),
                                                                    a, al,
                                                                    k, kl))

def zfec_encode(k, n, input_bytes):
    """
    ZFEC-encode an input message according to the given parameters

    :param int k: the number of shares required to recover the original
    :param int n: the total number of shares
    :param bytes input_bytes: the input message, in bytes

    :returns: n arrays of bytes, each one containing a single share
    """
    input_size = len(input_bytes)
    # note: the C++ code checks that input_bytes is a multiple of k
    outsize = input_size // k
    p_p_nbytes = c_char_p * n

    # allocate memory for the outputs (create_string_buffer makes bytes)
    outputs = [
        create_string_buffer(outsize)
        for a in range(n)
    ]

    c_outputs = p_p_nbytes(*[
        addressof(output)
        for output in outputs
    ])

    # actual C call
    _DLL.botan_zfec_encode(
        c_size_t(k), c_size_t(n), input_bytes, c_size_t(input_size), c_outputs
    )
    return [output.raw for output in outputs]


def zfec_decode(k, n, indexes, inputs):
    """
    ZFEC decode

    :param int k: the number of shares required to recover the original
    :param int n: the total number of shares
    :param list[int] indexes: which of the shares are we giving the decoder
    :param list[bytes] inputs: the input shares (e.g. from a previous
        call to zfec_encode) which all must be the same length

    :returns: a list of bytes containing the original shares decoded
        from the provided shares (in `inputs`)
    """

    if len(inputs) < k:
        raise BotanException('Insufficient inputs for zfec decoding')

    p_size_t = c_size_t * len(indexes)
    c_indexes = p_size_t(*[c_size_t(index) for index in indexes])
    p_p_nbytes = c_char_p * n
    c_inputs = p_p_nbytes(*[c_char_p(inp) for inp in inputs])
    # all inputs must be the same length
    share_size = len(inputs[0])
    for i in inputs:
        if len(i) != share_size:
            raise ValueError(
                "Share size mismatch: {} != {}".format(len(i), share_size)
            )

    # allocate memory for our outputs (create_string_buffer creates
    # bytes)
    outputs = [
        create_string_buffer(share_size)
        for _ in range(k)
    ]
    p_p_kbytes = c_char_p * k
    c_outputs = p_p_kbytes(*[
        addressof(output)
        for output in outputs
    ])

    # actual C call
    _DLL.botan_zfec_decode(
        c_size_t(k), c_size_t(n), c_indexes, c_inputs, c_size_t(share_size), c_outputs
    )
    return [output.raw for output in outputs]
