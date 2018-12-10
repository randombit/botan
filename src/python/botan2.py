#!/usr/bin/python

"""
Python wrapper of the botan crypto library
https://botan.randombit.net

(C) 2015,2017,2018 Jack Lloyd
(C) 2015 Uri  Blumenthal (extensions and patches)

Botan is released under the Simplified BSD License (see license.txt)

This module uses the ctypes module and is usable by programs running
under at least CPython 2.7, CPython 3.x, and PyPy

It uses botan's ffi module, which exposes a C API. This version of the
module requires FFI API version 20180713, which was introduced in
Botan 2.8

"""

from ctypes import CDLL, POINTER, byref, create_string_buffer, \
    c_void_p, c_size_t, c_uint8, c_uint32, c_uint64, c_int, c_char, c_char_p

from sys import version_info
from time import strptime, mktime
from binascii import hexlify
from datetime import datetime

BOTAN_FFI_VERSION = 20180713

#
# Base exception for all exceptions raised from this module
#
class BotanException(Exception):

    def __init__(self, message, rc=0):

        self.__rc = rc

        if rc == 0:
            super(BotanException, self).__init__(message)
        else:
            descr = botan.botan_error_description(rc).decode('ascii')
            super(BotanException, self).__init__("%s: %d (%s)" % (message, rc, descr))

    def error_code(self):
        return self.__rc

#
# Module initialization
#

def load_botan_dll(expected_version):

    possible_dll_names = ['libbotan-2.dylib', 'libbotan-2.so'] + \
                         ['libbotan-2.so.%d' % (v) for v in reversed(range(8, 16))]

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

botan = load_botan_dll(BOTAN_FFI_VERSION) # pylint: disable=invalid-name

if botan is None:
    raise BotanException("Could not find a usable Botan shared object library")

#
# ctypes function prototypes
#
def errcheck_for(fn_name):
    def errcheck(rc, _func, _args):
        # No idea what to do if return value isn't an int, just return it
        if not isinstance(rc, int):
            return rc

        if rc >= 0:
            return rc
        if rc == -10: # insufficient buffer space, pass up to caller
            return rc
        raise BotanException('%s failed' % (fn_name), rc)
    return errcheck

botan.botan_version_string.argtypes = []
botan.botan_version_string.restype = c_char_p

botan.botan_error_description.argtypes = [c_int]
botan.botan_error_description.restype = c_char_p

# RNG
botan.botan_rng_init.argtypes = [c_void_p, c_char_p]
botan.botan_rng_init.errcheck = errcheck_for('botan_rng_init')

botan.botan_rng_destroy.argtypes = [c_void_p]
botan.botan_rng_destroy.errcheck = errcheck_for('botan_rng_destroy')

botan.botan_rng_reseed.argtypes = [c_void_p, c_size_t]
botan.botan_rng_reseed.errcheck = errcheck_for('botan_rng_reseed')

botan.botan_rng_reseed_from_rng.argtypes = [c_void_p, c_void_p, c_size_t]
botan.botan_rng_reseed_from_rng.errcheck = errcheck_for('botan_rng_reseed_from_rng')

botan.botan_rng_add_entropy.argtypes = [c_void_p, c_char_p, c_size_t]
botan.botan_rng_add_entropy.errcheck = errcheck_for('botan_rng_add_entropy')

botan.botan_rng_get.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_rng_get.errcheck = errcheck_for('botan_rng_get')

# Hash function
botan.botan_hash_init.argtypes = [c_void_p, c_char_p, c_uint32]
botan.botan_hash_init.errcheck = errcheck_for('botan_hash_init')

botan.botan_hash_destroy.argtypes = [c_void_p]
botan.botan_hash_destroy.errcheck = errcheck_for('botan_hash_destroy')

botan.botan_hash_name.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_hash_name.errcheck = errcheck_for('botan_hash_name')

botan.botan_hash_clear.argtypes = [c_void_p]
botan.botan_hash_clear.errcheck = errcheck_for('botan_hash_clear')

botan.botan_hash_output_length.argtypes = [c_void_p, POINTER(c_size_t)]
botan.botan_hash_output_length.errcheck = errcheck_for('botan_hash_output_length')

botan.botan_hash_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_hash_update.errcheck = errcheck_for('botan_hash_update')

botan.botan_hash_final.argtypes = [c_void_p, POINTER(c_char)]
botan.botan_hash_final.errcheck = errcheck_for('botan_hash_final')

# MAC
botan.botan_mac_init.argtypes = [c_void_p, c_char_p, c_uint32]
botan.botan_mac_init.errcheck = errcheck_for('botan_mac_init')

botan.botan_mac_destroy.argtypes = [c_void_p]
botan.botan_mac_destroy.errcheck = errcheck_for('botan_mac_destroy')

botan.botan_mac_name.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_mac_name.errcheck = errcheck_for('botan_mac_name')

botan.botan_mac_clear.argtypes = [c_void_p]
botan.botan_mac_clear.errcheck = errcheck_for('botan_mac_clear')

botan.botan_mac_output_length.argtypes = [c_void_p, POINTER(c_size_t)]
botan.botan_mac_output_length.errcheck = errcheck_for('botan_mac_output_length')

botan.botan_mac_set_key.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_mac_set_key.errcheck = errcheck_for('botan_mac_set_key')

botan.botan_mac_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_mac_update.errcheck = errcheck_for('botan_mac_update')

botan.botan_mac_final.argtypes = [c_void_p, POINTER(c_char)]
botan.botan_mac_final.errcheck = errcheck_for('botan_mac_final')

# Cipher
botan.botan_cipher_init.argtypes = [c_void_p, c_char_p, c_uint32]
botan.botan_cipher_init.errcheck = errcheck_for('botan_cipher_init')

botan.botan_cipher_destroy.argtypes = [c_void_p]
botan.botan_cipher_destroy.errcheck = errcheck_for('botan_cipher_destroy')

botan.botan_cipher_reset.argtypes = [c_void_p]
botan.botan_cipher_reset.errcheck = errcheck_for('botan_cipher_reset')

botan.botan_cipher_name.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_cipher_name.errcheck = errcheck_for('botan_cipher_name')

botan.botan_cipher_get_default_nonce_length.argtypes = [c_void_p, POINTER(c_size_t)]
botan.botan_cipher_get_default_nonce_length.errcheck = errcheck_for('botan_cipher_get_default_nonce_length')

botan.botan_cipher_get_update_granularity.argtypes = [c_void_p, POINTER(c_size_t)]
botan.botan_cipher_get_update_granularity.errcheck = errcheck_for('botan_cipher_get_update_granularity')

botan.botan_cipher_get_tag_length.argtypes = [c_void_p, POINTER(c_size_t)]
botan.botan_cipher_get_tag_length.errcheck = errcheck_for('botan_cipher_get_tag_length')

botan.botan_cipher_valid_nonce_length.argtypes = [c_void_p, c_size_t]
botan.botan_cipher_valid_nonce_length.errcheck = errcheck_for('botan_cipher_valid_nonce_length')

botan.botan_cipher_clear.argtypes = [c_void_p]
botan.botan_cipher_clear.errcheck = errcheck_for('botan_cipher_clear')

botan.botan_cipher_set_key.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_cipher_set_key.errcheck = errcheck_for('botan_cipher_set_key')

botan.botan_cipher_set_associated_data.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_cipher_set_associated_data.errcheck = errcheck_for('botan_cipher_set_associated_data')

botan.botan_cipher_start.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_cipher_start.errcheck = errcheck_for('botan_cipher_start')

botan.botan_cipher_update.argtypes = [c_void_p, c_uint32,
                                      POINTER(c_char), c_size_t, POINTER(c_size_t),
                                      POINTER(c_char), c_size_t, POINTER(c_size_t)]
botan.botan_cipher_update.errcheck = errcheck_for('botan_cipher_update')

# Bcrypt
botan.botan_bcrypt_generate.argtypes = [POINTER(c_char), POINTER(c_size_t),
                                        c_char_p, c_void_p, c_size_t, c_uint32]
botan.botan_bcrypt_generate.errcheck = errcheck_for('botan_bcrypt_generate')

botan.botan_bcrypt_is_valid.argtypes = [c_char_p, c_char_p]
botan.botan_bcrypt_is_valid.errcheck = errcheck_for('botan_bcrypt_is_valid')

# PBKDF
botan.botan_pbkdf.argtypes = [c_char_p, POINTER(c_char), c_size_t, c_char_p, c_void_p, c_size_t, c_size_t]
botan.botan_pbkdf.errcheck = errcheck_for('botan_pbkdf')

botan.botan_pbkdf_timed.argtypes = [c_char_p, POINTER(c_char), c_size_t, c_char_p,
                                    c_void_p, c_size_t, c_size_t, POINTER(c_size_t)]
botan.botan_pbkdf_timed.errcheck = errcheck_for('botan_pbkdf_timed')

# Scrypt
botan.botan_scrypt.argtypes = [POINTER(c_char), c_size_t, c_char_p, POINTER(c_char), c_size_t,
                               c_size_t, c_size_t, c_size_t]
botan.botan_scrypt.errcheck = errcheck_for('botan_scrypt')

# KDF
botan.botan_kdf.argtypes = [c_char_p, POINTER(c_char), c_size_t, POINTER(c_char), c_size_t,
                            POINTER(c_char), c_size_t, POINTER(c_char), c_size_t]
botan.botan_kdf.errcheck = errcheck_for('botan_kdf')

# Public key
botan.botan_pubkey_destroy.argtypes = [c_void_p]
botan.botan_pubkey_destroy.errcheck = errcheck_for('botan_pubkey_destroy')

botan.botan_pubkey_estimated_strength.argtypes = [c_void_p, POINTER(c_size_t)]
botan.botan_pubkey_estimated_strength.errcheck = errcheck_for('botan_pubkey_estimated_strength')

botan.botan_pubkey_algo_name.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_pubkey_algo_name.errcheck = errcheck_for('botan_pubkey_algo_name')

botan.botan_pubkey_export.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t), c_uint32]
botan.botan_pubkey_export.errcheck = errcheck_for('botan_pubkey_export')

botan.botan_pubkey_fingerprint.argtypes = [c_void_p, c_char_p,
                                           POINTER(c_char), POINTER(c_size_t)]
botan.botan_pubkey_fingerprint.errcheck = errcheck_for('botan_pubkey_fingerprint')

botan.botan_privkey_create.argtypes = [c_void_p, c_char_p, c_char_p, c_void_p]
botan.botan_privkey_create.errcheck = errcheck_for('botan_privkey_create')

botan.botan_privkey_algo_name.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_privkey_algo_name.errcheck = errcheck_for('botan_privkey_algo_name')

botan.botan_privkey_export_pubkey.argtypes = [c_void_p, c_void_p]
botan.botan_privkey_export_pubkey.errcheck = errcheck_for('botan_privkey_export_pubkey')

botan.botan_privkey_destroy.argtypes = [c_void_p]
botan.botan_privkey_destroy.errcheck = errcheck_for('botan_privkey_destroy')

botan.botan_privkey_export.argtypes = [c_void_p, POINTER(c_char), c_void_p]
botan.botan_privkey_export.errcheck = errcheck_for('botan_privkey_export')

# PK Encryption
botan.botan_pk_op_encrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
botan.botan_pk_op_encrypt_create.errcheck = errcheck_for('botan_pk_op_encrypt_create')

botan.botan_pk_op_encrypt_output_length.argtypes = [c_void_p, c_size_t, POINTER(c_size_t)]
botan.botan_pk_op_encrypt_output_length.errcheck = errcheck_for('botan_pk_op_encrypt_output_length')

botan.botan_pk_op_encrypt_destroy.argtypes = [c_void_p]
botan.botan_pk_op_encrypt_destroy.errcheck = errcheck_for('botan_pk_op_encrypt_destroy')

botan.botan_pk_op_encrypt.argtypes = [c_void_p, c_void_p,
                                      POINTER(c_char), POINTER(c_size_t),
                                      POINTER(c_char), c_size_t]
botan.botan_pk_op_encrypt.errcheck = errcheck_for('botan_pk_op_encrypt')

# PK Decryption
botan.botan_pk_op_decrypt_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
botan.botan_pk_op_decrypt_create.errcheck = errcheck_for('botan_pk_op_decrypt_create')

botan.botan_pk_op_decrypt_output_length.argtypes = [c_void_p, c_size_t, POINTER(c_size_t)]
botan.botan_pk_op_decrypt_output_length.errcheck = errcheck_for('botan_pk_op_decrypt_output_length')

botan.botan_pk_op_decrypt_destroy.argtypes = [c_void_p]
botan.botan_pk_op_decrypt_destroy.errcheck = errcheck_for('botan_pk_op_decrypt_destroy')

botan.botan_pk_op_decrypt.argtypes = [c_void_p,
                                      POINTER(c_char), POINTER(c_size_t),
                                      POINTER(c_char), c_size_t]
botan.botan_pk_op_decrypt.errcheck = errcheck_for('botan_pk_op_encrypt')

# PK Signatures
botan.botan_pk_op_sign_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
botan.botan_pk_op_sign_create.errcheck = errcheck_for('botan_pk_op_sign_create')

botan.botan_pk_op_sign_destroy.argtypes = [c_void_p]
botan.botan_pk_op_sign_destroy.errcheck = errcheck_for('botan_pk_op_sign_destroy')

botan.botan_pk_op_sign_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_pk_op_sign_update.errcheck = errcheck_for('botan_pk_op_sign_update')

botan.botan_pk_op_sign_finish.argtypes = [c_void_p, c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_pk_op_sign_finish.errcheck = errcheck_for('botan_pk_op_sign_finish')

# PK Verification
botan.botan_pk_op_verify_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
botan.botan_pk_op_verify_create.errcheck = errcheck_for('botan_pk_op_verify_create')

botan.botan_pk_op_verify_destroy.argtypes = [c_void_p]
botan.botan_pk_op_verify_destroy.errcheck = errcheck_for('botan_pk_op_verify_destroy')

botan.botan_pk_op_verify_update.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_pk_op_verify_update.errcheck = errcheck_for('botan_pk_op_verify_update')

botan.botan_pk_op_verify_finish.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_pk_op_verify_finish.errcheck = errcheck_for('botan_pk_op_verify_finish')

# MCEIES
botan.botan_mceies_encrypt.argtypes = [c_void_p, c_void_p, c_char_p, POINTER(c_char), c_size_t,
                                       POINTER(c_char), c_size_t, POINTER(c_char), POINTER(c_size_t)]
botan.botan_mceies_encrypt.errcheck = errcheck_for('botan_mceies_encrypt')

botan.botan_mceies_decrypt.argtypes = [c_void_p, c_char_p, POINTER(c_char), c_size_t,
                                       POINTER(c_char), c_size_t, POINTER(c_char), POINTER(c_size_t)]
botan.botan_mceies_decrypt.errcheck = errcheck_for('botan_mceies_decrypt')

# Key Agreement
botan.botan_pk_op_key_agreement_export_public.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_pk_op_key_agreement_export_public.errcheck = errcheck_for('botan_pk_op_key_agreement_export_public')

botan.botan_pk_op_key_agreement_create.argtypes = [c_void_p, c_void_p, c_char_p, c_uint32]
botan.botan_pk_op_key_agreement_create.errcheck = errcheck_for('botan_pk_op_key_agreement_create')

botan.botan_pk_op_key_agreement_destroy.argtypes = [c_void_p]
botan.botan_pk_op_key_agreement_destroy.errcheck = errcheck_for('botan_pk_op_key_agreement_destroy')

botan.botan_pk_op_key_agreement.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t),
                                            POINTER(c_char), c_size_t, POINTER(c_char), c_size_t]
botan.botan_pk_op_key_agreement.errcheck = errcheck_for('botan_pk_op_key_agreement')

# X509 certs
botan.botan_x509_cert_load_file.argtypes = [POINTER(c_void_p), c_char_p]
botan.botan_x509_cert_load_file.errcheck = errcheck_for('botan_x509_cert_load_file')

botan.botan_x509_cert_load.argtypes = [POINTER(c_void_p), POINTER(c_char), c_size_t]
botan.botan_x509_cert_load.errcheck = errcheck_for('botan_x509_cert_load')

botan.botan_x509_cert_destroy.argtypes = [c_void_p]
botan.botan_x509_cert_destroy.errcheck = errcheck_for('botan_x509_cert_destroy')

botan.botan_x509_cert_get_time_starts.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_get_time_starts.errcheck = errcheck_for('botan_x509_cert_get_time_starts')

botan.botan_x509_cert_get_time_expires.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_get_time_expires.errcheck = errcheck_for('botan_x509_cert_get_time_expires')

botan.botan_x509_cert_to_string.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_to_string.errcheck = errcheck_for('botan_x509_cert_to_string')

botan.botan_x509_cert_get_fingerprint.argtypes = [c_void_p, c_char_p,
                                                  POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_get_fingerprint.errcheck = errcheck_for('botan_x509_cert_get_fingerprint')

botan.botan_x509_cert_get_serial_number.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_get_serial_number.errcheck = errcheck_for('botan_x509_cert_get_serial_number')

botan.botan_x509_cert_get_authority_key_id.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_get_authority_key_id.errcheck = errcheck_for('botan_x509_cert_get_authority_key_id')

botan.botan_x509_cert_get_subject_key_id.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_get_subject_key_id.errcheck = errcheck_for('botan_x509_cert_get_subject_key_id')

botan.botan_x509_cert_get_public_key_bits.argtypes = [c_void_p, POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_get_public_key_bits.errcheck = errcheck_for('botan_x509_cert_get_public_key_bits')

botan.botan_x509_cert_get_public_key.argtypes = [c_void_p, c_void_p]
botan.botan_x509_cert_get_public_key.errcheck = errcheck_for('botan_x509_cert_get_public_key')

botan.botan_x509_cert_get_subject_dn.argtypes = [c_void_p, c_char_p, c_size_t, POINTER(c_char), POINTER(c_size_t)]
botan.botan_x509_cert_get_subject_dn.errcheck = errcheck_for('botan_x509_cert_get_subject_dn')

# MPI
botan.botan_mp_init.argtypes = [c_void_p]
botan.botan_mp_init.errcheck = errcheck_for('botan_mp_init')
botan.botan_mp_destroy.argtypes = [c_void_p]
botan.botan_mp_destroy.errcheck = errcheck_for('botan_mp_destroy')

botan.botan_mp_to_hex.argtypes = [c_void_p, POINTER(c_char)]
botan.botan_mp_to_hex.errcheck = errcheck_for('botan_mp_to_hex')
botan.botan_mp_to_str.argtypes = [c_void_p, c_uint8, POINTER(c_char), POINTER(c_size_t)]
botan.botan_mp_to_str.errcheck = errcheck_for('botan_mp_to_str')

botan.botan_mp_clear.argtypes = [c_void_p]
botan.botan_mp_clear.errcheck = errcheck_for('botan_mp_clear')

botan.botan_mp_set_from_int.argtypes = [c_void_p, c_int]
botan.botan_mp_set_from_int.errcheck = errcheck_for('botan_mp_set_from_int')
botan.botan_mp_set_from_mp.argtypes = [c_void_p, c_void_p]
botan.botan_mp_set_from_mp.errcheck = errcheck_for('botan_mp_set_from_mp')
botan.botan_mp_set_from_str.argtypes = [c_void_p, POINTER(c_char)]
botan.botan_mp_set_from_str.errcheck = errcheck_for('botan_mp_set_from_str')
botan.botan_mp_set_from_radix_str.argtypes = [c_void_p, POINTER(c_char), c_size_t]
botan.botan_mp_set_from_radix_str.errcheck = errcheck_for('botan_mp_set_from_radix_str')

botan.botan_mp_num_bits.argtypes = [c_void_p, POINTER(c_size_t)]
botan.botan_mp_num_bits.errcheck = errcheck_for('botan_mp_num_bits')
botan.botan_mp_num_bytes.argtypes = [c_void_p, POINTER(c_size_t)]
botan.botan_mp_num_bytes.errcheck = errcheck_for('botan_mp_num_bytes')

botan.botan_mp_to_bin.argtypes = [c_void_p, POINTER(c_uint8)]
botan.botan_mp_to_bin.errcheck = errcheck_for('botan_mp_to_bin')
botan.botan_mp_from_bin.argtypes = [c_void_p, POINTER(c_uint8), c_size_t]
botan.botan_mp_from_bin.errcheck = errcheck_for('botan_mp_from_bin')

botan.botan_mp_to_uint32.argtypes = [c_void_p, POINTER(c_uint32)]
botan.botan_mp_to_uint32.errcheck = errcheck_for('botan_mp_to_uint32')

botan.botan_mp_is_positive.argtypes = [c_void_p]
botan.botan_mp_is_positive.errcheck = errcheck_for('botan_mp_is_positive')

botan.botan_mp_is_negative.argtypes = [c_void_p]
botan.botan_mp_is_negative.errcheck = errcheck_for('botan_mp_is_negative')

botan.botan_mp_flip_sign.argtypes = [c_void_p]
botan.botan_mp_flip_sign.errcheck = errcheck_for('botan_mp_flip_sign')

botan.botan_mp_is_zero.argtypes = [c_void_p]
botan.botan_mp_is_zero.errcheck = errcheck_for('botan_mp_is_zero')
botan.botan_mp_is_odd.argtypes = [c_void_p]
botan.botan_mp_is_odd.errcheck = errcheck_for('botan_mp_is_odd')
botan.botan_mp_is_even.argtypes = [c_void_p]
botan.botan_mp_is_even.errcheck = errcheck_for('botan_mp_is_even')

botan.botan_mp_add.argtypes = [c_void_p, c_void_p, c_void_p]
botan.botan_mp_add.errcheck = errcheck_for('botan_mp_add')
botan.botan_mp_sub.argtypes = [c_void_p, c_void_p, c_void_p]
botan.botan_mp_sub.errcheck = errcheck_for('botan_mp_sub')
botan.botan_mp_mul.argtypes = [c_void_p, c_void_p, c_void_p]
botan.botan_mp_mul.errcheck = errcheck_for('botan_mp_mul')

botan.botan_mp_div.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
botan.botan_mp_div.errcheck = errcheck_for('botan_mp_div')

botan.botan_mp_mod_mul.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
botan.botan_mp_mod_mul.errcheck = errcheck_for('botan_mp_mod_mul')

botan.botan_mp_equal.argtypes = [c_void_p, c_void_p]
botan.botan_mp_equal.errcheck = errcheck_for('botan_mp_equal')

botan.botan_mp_cmp.argtypes = [POINTER(c_int), c_void_p, c_void_p]
botan.botan_mp_cmp.errcheck = errcheck_for('botan_mp_cmp')

botan.botan_mp_swap.argtypes = [c_void_p, c_void_p]
botan.botan_mp_swap.errcheck = errcheck_for('botan_mp_swap')

botan.botan_mp_powmod.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
botan.botan_mp_powmod.errcheck = errcheck_for('botan_mp_powmod')

botan.botan_mp_lshift.argtypes = [c_void_p, c_void_p, c_size_t]
botan.botan_mp_lshift.errcheck = errcheck_for('botan_mp_lshift')
botan.botan_mp_rshift.argtypes = [c_void_p, c_void_p, c_size_t]
botan.botan_mp_rshift.errcheck = errcheck_for('botan_mp_rshift')

botan.botan_mp_mod_inverse.argtypes = [c_void_p, c_void_p, c_void_p]
botan.botan_mp_mod_inverse.errcheck = errcheck_for('botan_mp_mod_inverse')

botan.botan_mp_rand_bits.argtypes = [c_void_p, c_void_p, c_size_t]
botan.botan_mp_rand_bits.errcheck = errcheck_for('botan_mp_rand_bits')

botan.botan_mp_rand_range.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
botan.botan_mp_rand_range.errcheck = errcheck_for('botan_mp_rand_range')

botan.botan_mp_gcd.argtypes = [c_void_p, c_void_p, c_void_p]
botan.botan_mp_gcd.errcheck = errcheck_for('botan_mp_gcd')

botan.botan_mp_is_prime.argtypes = [c_void_p, c_void_p, c_size_t]
botan.botan_mp_is_prime.errcheck = errcheck_for('botan_mp_is_prime')

botan.botan_mp_get_bit.argtypes = [c_void_p, c_size_t]
botan.botan_mp_get_bit.errcheck = errcheck_for('botan_mp_get_bit')

botan.botan_mp_set_bit.argtypes = [c_void_p, c_size_t]
botan.botan_mp_set_bit.errcheck = errcheck_for('botan_mp_set_bit')

botan.botan_mp_clear_bit.argtypes = [c_void_p, c_size_t]
botan.botan_mp_clear_bit.errcheck = errcheck_for('botan_mp_clear_bit')

#
# FPE
#
botan.botan_fpe_fe1_init.argtypes = [c_void_p, c_void_p, POINTER(c_char), c_size_t, c_size_t, c_uint32]
botan.botan_fpe_fe1_init.errcheck = errcheck_for('botan_fpe_fe1_init')

botan.botan_fpe_destroy.argtypes = [c_void_p]
botan.botan_fpe_destroy.errcheck = errcheck_for('botan_fpe_destroy')

botan.botan_fpe_encrypt.argtypes = [c_void_p, c_void_p, POINTER(c_char), c_size_t]
botan.botan_fpe_encrypt.errcheck = errcheck_for('botan_fpe_encrypt')
botan.botan_fpe_decrypt.argtypes = [c_void_p, c_void_p, POINTER(c_char), c_size_t]
botan.botan_fpe_decrypt.errcheck = errcheck_for('botan_fpe_decrypt')

#
# HOTP
#
botan.botan_hotp_init.argtype = [c_void_p, POINTER(c_char), c_size_t, c_char_p, c_size_t]
botan.botan_hotp_init.errcheck = errcheck_for('botan_hotp_init')

botan.botan_hotp_destroy.argtype = [c_void_p]
botan.botan_hotp_destroy.errcheck = errcheck_for('botan_hotp_destroy')

botan.botan_hotp_generate.argtype = [c_void_p, POINTER(c_uint32), c_uint64]
botan.botan_hotp_generate.errcheck = errcheck_for('botan_hotp_generate')

botan.botan_hotp_check.argtype = [c_void_p, POINTER(c_uint64), c_uint32, c_uint64, c_size_t]
botan.botan_hotp_check.errcheck = errcheck_for('botan_hotp_check')

#
# Internal utilities
#
def _call_fn_returning_vec(guess, fn):

    buf = create_string_buffer(guess)
    buf_len = c_size_t(len(buf))

    rc = fn(buf, byref(buf_len))
    if rc == -10 and buf_len.value > len(buf):
        return _call_fn_returning_vec(buf_len.value, fn)

    assert buf_len.value <= len(buf)
    return buf.raw[0:int(buf_len.value)]

def _call_fn_returning_string(guess, fn):
    # Assumes that anything called with this is returning plain ASCII strings
    # (base64 data, algorithm names, etc)
    v = _call_fn_returning_vec(guess, fn)
    return v.decode('ascii')[:-1]

def _ctype_str(s):
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
# Versions
#
def version_major():
    return botan.botan_version_major()

def version_minor():
    return botan.botan_version_minor()

def version_patch():
    return botan.botan_version_patch()

def version_string():
    return botan.botan_version_string().decode('ascii')

#
# RNG
#
class RandomNumberGenerator(object):
    # Can also use type "system"
    def __init__(self, rng_type='system'):
        self.__obj = c_void_p(0)
        botan.botan_rng_init(byref(self.__obj), _ctype_str(rng_type))

    def __del__(self):
        botan.botan_rng_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def reseed(self, bits=256):
        botan.botan_rng_reseed(self.__obj, bits)

    def reseed_from_rng(self, source_rng, bits=256):
        botan.botan_rng_reseed_from_rng(self.__obj, source_rng.handle_(), bits)

    def add_entropy(self, seed):
        botan.botan_rng_add_entropy(self.__obj, _ctype_bits(seed), len(seed))

    def get(self, length):
        out = create_string_buffer(length)
        l = c_size_t(length)
        botan.botan_rng_get(self.__obj, out, l)
        return _ctype_bufout(out)

#
# Hash function
#
class HashFunction(object):
    def __init__(self, algo):
        flags = c_uint32(0) # always zero in this API version
        self.__obj = c_void_p(0)
        botan.botan_hash_init(byref(self.__obj), _ctype_str(algo), flags)

        output_length = c_size_t(0)
        botan.botan_hash_output_length(self.__obj, byref(output_length))
        self.__output_length = output_length.value

    def __del__(self):
        botan.botan_hash_destroy(self.__obj)

    def algo_name(self):
        return _call_fn_returning_string(32, lambda b, bl: botan.botan_hash_name(self.__obj, b, bl))

    def clear(self):
        botan.botan_hash_clear(self.__obj)

    def output_length(self):
        return self.__output_length

    def update(self, x):
        botan.botan_hash_update(self.__obj, _ctype_bits(x), len(x))

    def final(self):
        out = create_string_buffer(self.output_length())
        botan.botan_hash_final(self.__obj, out)
        return _ctype_bufout(out)

#
# Message authentication codes
#
class MsgAuthCode(object):
    def __init__(self, algo):
        flags = c_uint32(0) # always zero in this API version
        self.__obj = c_void_p(0)
        botan.botan_mac_init(byref(self.__obj), _ctype_str(algo), flags)

        min_keylen = c_size_t(0)
        max_keylen = c_size_t(0)
        mod_keylen = c_size_t(0)
        botan.botan_mac_get_keyspec(self.__obj, byref(min_keylen), byref(max_keylen), byref(mod_keylen))

        self.__min_keylen = min_keylen.value
        self.__max_keylen = max_keylen.value
        self.__mod_keylen = mod_keylen.value

        output_length = c_size_t(0)
        botan.botan_mac_output_length(self.__obj, byref(output_length))
        self.__output_length = output_length.value

    def __del__(self):
        botan.botan_mac_destroy(self.__obj)

    def clear(self):
        botan.botan_mac_clear(self.__obj)

    def algo_name(self):
        return _call_fn_returning_string(32, lambda b, bl: botan.botan_mac_name(self.__obj, b, bl))

    def output_length(self):
        return self.__output_length

    def minimum_keylength(self):
        return self.__min_keylen

    def maximum_keylength(self):
        return self.__max_keylen

    def set_key(self, key):
        botan.botan_mac_set_key(self.__obj, key, len(key))

    def update(self, x):
        botan.botan_mac_update(self.__obj, x, len(x))

    def final(self):
        out = create_string_buffer(self.output_length())
        botan.botan_mac_final(self.__obj, out)
        return _ctype_bufout(out)

class SymmetricCipher(object):
    def __init__(self, algo, encrypt=True):
        flags = 0 if encrypt else 1
        self.__obj = c_void_p(0)
        botan.botan_cipher_init(byref(self.__obj), _ctype_str(algo), flags)

    def __del__(self):
        botan.botan_cipher_destroy(self.__obj)

    def algo_name(self):
        return _call_fn_returning_string(32, lambda b, bl: botan.botan_cipher_name(self.__obj, b, bl))

    def default_nonce_length(self):
        l = c_size_t(0)
        botan.botan_cipher_get_default_nonce_length(self.__obj, byref(l))
        return l.value

    def update_granularity(self):
        l = c_size_t(0)
        botan.botan_cipher_get_update_granularity(self.__obj, byref(l))
        return l.value

    def key_length(self):
        kmin = c_size_t(0)
        kmax = c_size_t(0)
        botan.botan_cipher_query_keylen(self.__obj, byref(kmin), byref(kmax))
        return kmin.value, kmax.value

    def minimum_keylength(self):
        l = c_size_t(0)
        botan.botan_cipher_get_keyspec(self.__obj, byref(l), None, None)
        return l.value

    def maximum_keylength(self):
        l = c_size_t(0)
        botan.botan_cipher_get_keyspec(self.__obj, None, byref(l), None)
        return l.value

    def tag_length(self):
        l = c_size_t(0)
        botan.botan_cipher_get_tag_length(self.__obj, byref(l))
        return l.value

    def is_authenticated(self):
        return self.tag_length() > 0

    def valid_nonce_length(self, nonce_len):
        rc = botan.botan_cipher_valid_nonce_length(self.__obj, nonce_len)
        return rc == 1

    def reset(self):
        botan.botan_cipher_reset(self.__obj)

    def clear(self):
        botan.botan_cipher_clear(self.__obj)

    def set_key(self, key):
        botan.botan_cipher_set_key(self.__obj, key, len(key))

    def set_assoc_data(self, ad):
        botan.botan_cipher_set_associated_data(self.__obj, ad, len(ad))

    def start(self, nonce):
        botan.botan_cipher_start(self.__obj, nonce, len(nonce))

    def _update(self, txt, final):

        inp = txt if txt else ''
        inp_sz = c_size_t(len(inp))
        inp_consumed = c_size_t(0)
        out = create_string_buffer(inp_sz.value + (self.tag_length() if final else 0))
        out_sz = c_size_t(len(out))
        out_written = c_size_t(0)
        flags = c_uint32(1 if final else 0)

        botan.botan_cipher_update(self.__obj, flags,
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
    botan.botan_bcrypt_generate(out, byref(out_len), _ctype_str(passwd),
                                rng_obj.handle_(), c_size_t(work_factor), flags)
    b = out.raw[0:int(out_len.value)-1]
    if b[-1] == '\x00':
        b = b[:-1]
    return _ctype_to_str(b)

def check_bcrypt(passwd, passwd_hash):
    rc = botan.botan_bcrypt_is_valid(_ctype_str(passwd), _ctype_str(passwd_hash))
    return rc == 0

#
# PBKDF
#
def pbkdf(algo, password, out_len, iterations=10000, salt=None):
    if salt is None:
        salt = RandomNumberGenerator().get(12)
    out_buf = create_string_buffer(out_len)
    botan.botan_pbkdf(_ctype_str(algo), out_buf, out_len,
                      _ctype_str(password), salt, len(salt), iterations)
    return (salt, iterations, out_buf.raw)

def pbkdf_timed(algo, password, out_len, ms_to_run=300, salt=None):
    if salt is None:
        salt = RandomNumberGenerator().get(12)
    out_buf = create_string_buffer(out_len)
    iterations = c_size_t(0)
    botan.botan_pbkdf_timed(_ctype_str(algo), out_buf, out_len, _ctype_str(password),
                            salt, len(salt), ms_to_run, byref(iterations))
    return (salt, iterations.value, out_buf.raw)

#
# Scrypt
#
def scrypt(out_len, password, salt, n=1024, r=8, p=8):
    out_buf = create_string_buffer(out_len)
    botan.botan_scrypt(out_buf, out_len, _ctype_str(password),
                       _ctype_bits(salt), len(salt), n, r, p)

    return out_buf.raw

#
# KDF
#
def kdf(algo, secret, out_len, salt, label):
    out_buf = create_string_buffer(out_len)
    out_sz = c_size_t(out_len)
    botan.botan_kdf(_ctype_str(algo), out_buf, out_sz,
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

    def __del__(self):
        botan.botan_pubkey_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def estimated_strength(self):
        r = c_size_t(0)
        botan.botan_pubkey_estimated_strength(self.__obj, byref(r))
        return r.value

    def algo_name(self):
        return _call_fn_returning_string(32, lambda b, bl: botan.botan_pubkey_algo_name(self.__obj, b, bl))

    def encoding(self, pem=False):
        flag = 1 if pem else 0
        return _call_fn_returning_vec(4096, lambda b, bl: botan.botan_pubkey_export(self.__obj, b, bl, flag))

    def fingerprint(self, hash_algorithm='SHA-256'):

        n = HashFunction(hash_algorithm).output_length()
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)

        botan.botan_pubkey_fingerprint(self.__obj, _ctype_str(hash_algorithm), buf, byref(buf_len))
        return _hex_encode(buf[0:int(buf_len.value)])

#
# Private Key
#
class PrivateKey(object):
    def __init__(self, algo, params, rng_obj):

        self.__obj = c_void_p(0)

        if algo == 'rsa':
            algo = 'RSA'
            params = "%d" % (params)
        elif algo == 'ecdsa':
            algo = 'ECDSA'
        elif algo == 'ecdh':

            if params == 'curve25519':
                algo = 'Curve25519'
                params = ''
            else:
                algo = 'ECDH'

        elif algo in ['mce', 'mceliece']:
            algo = 'McEliece'
            params = "%d,%d" % (params[0], params[1])

        botan.botan_privkey_create(byref(self.__obj),
                                   _ctype_str(algo), _ctype_str(params), rng_obj.handle_())

    def __del__(self):
        botan.botan_privkey_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def algo_name(self):
        return _call_fn_returning_string(32, lambda b, bl: botan.botan_privkey_algo_name(self.__obj, b, bl))

    def get_public_key(self):

        pub = c_void_p(0)
        botan.botan_privkey_export_pubkey(byref(pub), self.__obj)
        return public_key(pub)

    def export(self):

        n = 4096
        buf = create_string_buffer(n)
        buf_len = c_size_t(n)

        rc = botan.botan_privkey_export(self.__obj, buf, byref(buf_len))
        if rc != 0:
            buf = create_string_buffer(buf_len.value)
            botan.botan_privkey_export(self.__obj, buf, byref(buf_len))
        return buf[0:int(buf_len.value)]

class PKEncrypt(object):
    def __init__(self, key, padding):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_encrypt_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        botan.botan_pk_op_encrypt_destroy(self.__obj)

    def encrypt(self, msg, rng_obj):
        outbuf_sz = c_size_t(0)
        botan.botan_pk_op_encrypt_output_length(self.__obj, len(msg), byref(outbuf_sz))
        outbuf = create_string_buffer(outbuf_sz.value)
        botan.botan_pk_op_encrypt(self.__obj, rng_obj.handle_(), outbuf, byref(outbuf_sz), msg, len(msg))
        return outbuf.raw[0:int(outbuf_sz.value)]


class PKDecrypt(object):
    def __init__(self, key, padding):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_decrypt_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        botan.botan_pk_op_decrypt_destroy(self.__obj)

    def decrypt(self, msg):
        outbuf_sz = c_size_t(0)
        botan.botan_pk_op_decrypt_output_length(self.__obj, len(msg), byref(outbuf_sz))
        outbuf = create_string_buffer(outbuf_sz.value)
        botan.botan_pk_op_decrypt(self.__obj, outbuf, byref(outbuf_sz), _ctype_bits(msg), len(msg))
        return outbuf.raw[0:int(outbuf_sz.value)]

class PKSign(object): # pylint: disable=invalid-name
    def __init__(self, key, padding):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_sign_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        botan.botan_pk_op_sign_destroy(self.__obj)

    def update(self, msg):
        botan.botan_pk_op_sign_update(self.__obj, _ctype_str(msg), len(msg))

    def finish(self, rng_obj):
        outbuf_sz = c_size_t(0)
        botan.botan_pk_op_sign_output_length(self.__obj, byref(outbuf_sz))
        outbuf = create_string_buffer(outbuf_sz.value)
        botan.botan_pk_op_sign_finish(self.__obj, rng_obj.handle_(), outbuf, byref(outbuf_sz))
        return outbuf.raw[0:int(outbuf_sz.value)]

class PKVerify(object):
    def __init__(self, key, padding):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_verify_create(byref(self.__obj), key.handle_(), _ctype_str(padding), flags)

    def __del__(self):
        botan.botan_pk_op_verify_destroy(self.__obj)

    def update(self, msg):
        botan.botan_pk_op_verify_update(self.__obj, _ctype_bits(msg), len(msg))

    def check_signature(self, signature):
        rc = botan.botan_pk_op_verify_finish(self.__obj, _ctype_bits(signature), len(signature))
        if rc == 0:
            return True
        return False

class PKKeyAgreement(object):
    def __init__(self, key, kdf_name):
        self.__obj = c_void_p(0)
        flags = c_uint32(0) # always zero in this ABI
        botan.botan_pk_op_key_agreement_create(byref(self.__obj), key.handle_(), kdf_name, flags)

        self.m_public_value = _call_fn_returning_vec(
            0, lambda b, bl: botan.botan_pk_op_key_agreement_export_public(key.handle_(), b, bl))

    def __del__(self):
        botan.botan_pk_op_key_agreement_destroy(self.__obj)

    def public_value(self):
        return self.m_public_value

    def agree(self, other, key_len, salt):
        return _call_fn_returning_vec(key_len, lambda b, bl:
                                      botan.botan_pk_op_key_agreement(self.__obj, b, bl,
                                                                      other, len(other),
                                                                      salt, len(salt)))

#
# MCEIES encryption
# Must be used with McEliece keys
#
def mceies_encrypt(mce, rng_obj, aead, pt, ad):
    return _call_fn_returning_vec(len(pt) + 1024, lambda b, bl:
                                  botan.botan_mceies_encrypt(mce.handle_(),
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
                                  botan.botan_mceies_decrypt(mce.handle_(),
                                                             _ctype_str(aead),
                                                             _ctype_bits(ct),
                                                             len(ct),
                                                             _ctype_bits(ad),
                                                             len(ad),
                                                             b, bl))


#
# X.509 certificates
#
class X509Cert(object): # pylint: disable=invalid-name
    def __init__(self, filename=None, buf=None):
        if filename is None and buf is None:
            raise BotanException("No filename or buf given")
        if filename is not None and buf is not None:
            raise BotanException("Both filename and buf given")
        elif filename is not None:
            self.__obj = c_void_p(0)
            botan.botan_x509_cert_load_file(byref(self.__obj), _ctype_str(filename))
        elif buf is not None:
            self.__obj = c_void_p(0)
            botan.botan_x509_cert_load(byref(self.__obj), _ctype_bits(buf), len(buf))

    def __del__(self):
        botan.botan_x509_cert_destroy(self.__obj)

    def time_starts(self):
        starts = _call_fn_returning_string(
            16, lambda b, bl: botan.botan_x509_cert_get_time_starts(self.__obj, b, bl))
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
        expires = _call_fn_returning_string(
            16, lambda b, bl: botan.botan_x509_cert_get_time_expires(self.__obj, b, bl))
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
        return _call_fn_returning_string(
            4096, lambda b, bl: botan.botan_x509_cert_to_string(self.__obj, b, bl))

    def fingerprint(self, hash_algo='SHA-256'):
        n = HashFunction(hash_algo).output_length() * 3
        return _call_fn_returning_string(
            n, lambda b, bl: botan.botan_x509_cert_get_fingerprint(self.__obj, _ctype_str(hash_algo), b, bl))

    def serial_number(self):
        return _call_fn_returning_vec(
            32, lambda b, bl: botan.botan_x509_cert_get_serial_number(self.__obj, b, bl))

    def authority_key_id(self):
        return _call_fn_returning_vec(
            32, lambda b, bl: botan.botan_x509_cert_get_authority_key_id(self.__obj, b, bl))

    def subject_key_id(self):
        return _call_fn_returning_vec(
            32, lambda b, bl: botan.botan_x509_cert_get_subject_key_id(self.__obj, b, bl))

    def subject_public_key_bits(self):
        return _call_fn_returning_vec(
            512, lambda b, bl: botan.botan_x509_cert_get_public_key_bits(self.__obj, b, bl))

    def subject_public_key(self):
        pub = c_void_p(0)
        botan.botan_x509_cert_get_public_key(self.__obj, byref(pub))
        return public_key(pub)

    def subject_dn(self, key, index):
        return _call_fn_returning_string(
            0, lambda b, bl: botan.botan_x509_cert_get_subject_dn(self.__obj, _ctype_str(key), index, b, bl))


class MPI(object):

    def __init__(self, initial_value=None):

        self.__obj = c_void_p(0)
        botan.botan_mp_init(byref(self.__obj))

        if initial_value is None:
            pass # left as zero
        elif isinstance(initial_value, MPI):
            botan.botan_mp_set_from_mp(self.__obj, initial_value.handle_())
        elif isinstance(initial_value, str):
            botan.botan_mp_set_from_str(self.__obj, _ctype_str(initial_value))
        else:
            # For int or long (or whatever else), try converting to string:
            botan.botan_mp_set_from_str(self.__obj, _ctype_str(str(initial_value)))

    def __del__(self):
        botan.botan_mp_destroy(self.__obj)

    def handle_(self):
        return self.__obj

    def __int__(self):
        out = create_string_buffer(2*self.byte_count() + 1)
        botan.botan_mp_to_hex(self.__obj, out)
        val = int(out.value, 16)
        if self.is_negative():
            return -val
        else:
            return val

    def __repr__(self):
        # Should have a better size estimate than this ...
        out_len = c_size_t(self.bit_count() // 2)
        out = create_string_buffer(out_len.value)

        botan.botan_mp_to_str(self.__obj, c_uint8(10), out, byref(out_len))

        out = out.raw[0:int(out_len.value)]
        if out[-1] == '\x00':
            out = out[:-1]
        s = _ctype_to_str(out)
        if s[0] == '0':
            return s[1:]
        else:
            return s

    def is_negative(self):
        rc = botan.botan_mp_is_negative(self.__obj)
        return rc == 1

    def flip_sign(self):
        botan.botan_mp_flip_sign(self.__obj)

    def cmp(self, other):
        r = c_int(0)
        botan.botan_mp_cmp(byref(r), self.__obj, other.handle_())
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

    def __add__(self, other):
        r = MPI()
        botan.botan_mp_add(r.handle_(), self.__obj, other.handle_())
        return r

    def __iadd__(self, other):
        botan.botan_mp_add(self.__obj, self.__obj, other.handle_())
        return self

    def __sub__(self, other):
        r = MPI()
        botan.botan_mp_sub(r.handle_(), self.__obj, other.handle_())
        return r

    def __isub__(self, other):
        botan.botan_mp_sub(self.__obj, self.__obj, other.handle_())
        return self

    def __mul__(self, other):
        r = MPI()
        botan.botan_mp_mul(r.handle_(), self.__obj, other.handle_())
        return r

    def __imul__(self, other):
        botan.botan_mp_mul(self.__obj, self.__obj, other.handle_())
        return self

    def __divmod__(self, other):
        d = MPI()
        q = MPI()
        botan.botan_mp_div(d.handle_(), q.handle_(), self.__obj, other.handle_())
        return (d, q)

    def __mod__(self, other):
        d = MPI()
        q = MPI()
        botan.botan_mp_div(d.handle_(), q.handle_(), self.__obj, other.handle_())
        return q

    def __lshift__(self, shift):
        shift = c_size_t(shift)
        r = MPI()
        botan.botan_mp_lshift(r.handle_(), self.__obj, shift)
        return r

    def __ilshift__(self, shift):
        shift = c_size_t(shift)
        botan.botan_mp_lshift(self.__obj, self.__obj, shift)
        return self

    def __rshift__(self, shift):
        shift = c_size_t(shift)
        r = MPI()
        botan.botan_mp_rshift(r.handle_(), self.__obj, shift)
        return r

    def __irshift__(self, shift):
        shift = c_size_t(shift)
        botan.botan_mp_rshift(self.__obj, self.__obj, shift)
        return self

    def pow_mod(self, exponent, modulus):
        r = MPI()
        botan.botan_mp_powmod(r.handle_(), self.__obj, exponent.handle_(), modulus.handle_())
        return r

    def is_prime(self, rng_obj, prob=128):
        return botan.botan_mp_is_prime(self.__obj, rng_obj.handle_(), c_size_t(prob)) == 1

    def inverse_mod(self, modulus):
        r = MPI()
        botan.botan_mp_mod_inverse(r.handle_(), self.__obj, modulus.handle_())
        return r

    def bit_count(self):
        b = c_size_t(0)
        botan.botan_mp_num_bits(self.__obj, byref(b))
        return b.value

    def byte_count(self):
        b = c_size_t(0)
        botan.botan_mp_num_bytes(self.__obj, byref(b))
        return b.value

    def get_bit(self, bit):
        return botan.botan_mp_get_bit(self.__obj, c_size_t(bit)) == 1

    def clear_bit(self, bit):
        botan.botan_mp_clear_bit(self.__obj, c_size_t(bit))

    def set_bit(self, bit):
        botan.botan_mp_set_bit(self.__obj, c_size_t(bit))

class FormatPreservingEncryptionFE1(object):

    def __init__(self, modulus, key, rounds=5, compat_mode=False):
        flags = c_uint32(1 if compat_mode else 0)
        self.__obj = c_void_p(0)
        botan.botan_fpe_fe1_init(byref(self.__obj), modulus.handle_(), key, len(key), c_size_t(rounds), flags)

    def __del__(self):
        botan.botan_fpe_destroy(self.__obj)

    def encrypt(self, msg, tweak):
        r = MPI(msg)
        botan.botan_fpe_encrypt(self.__obj, r.handle_(), _ctype_bits(tweak), len(tweak))
        return r

    def decrypt(self, msg, tweak):
        r = MPI(msg)
        botan.botan_fpe_decrypt(self.__obj, r.handle_(), _ctype_bits(tweak), len(tweak))
        return r

class HOTP(object):
    def __init__(self, key, digest="SHA-1", digits=6):
        self.__obj = c_void_p(0)
        botan.botan_hotp_init(byref(self.__obj), key, len(key), _ctype_str(digest), digits)

    def __del__(self):
        botan.botan_hotp_destroy(self.__obj)

    def generate(self, counter):
        code = c_uint32(0)
        botan.botan_hotp_generate(self.__obj, byref(code), counter)
        return code.value

    def check(self, code, counter, resync_range=0):
        next_ctr = c_uint64(0)
        rc = botan.botan_hotp_check(self.__obj, byref(next_ctr), code, counter, resync_range)
        if rc == 0:
            return (True, next_ctr.value)
        else:
            return (False, counter)

# Typedefs for compat with older versions
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
