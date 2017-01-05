
FFI Interface
========================================

.. versionadded:: 1.11.14

Botan's ffi module provides a C API intended to be easily usable with
other language's foreign function interface (FFI) libraries. For
instance the Python module using the FFI interface needs only the
ctypes module (included in default Python) and works with

Versioning
----------------------------------------

.. cpp:function:: uint32_t botan_ffi_api_version()

   Returns the version of the currently supported FFI API.  This is
   expressed in the form YYYYMMDD of the release date of this version
   of the API.

.. cpp:function int botan_ffi_supports_api(uint32_t version)

   Return 0 iff the FFI version specified is supported by this
   library. Otherwise returns -1. The expression
   botan_ffi_supports_api(botan_ffi_api_version()) will always
   evaluate to 0. A particular version of the library may also support
   other (older) versions of the FFI API.

.. cpp:function:: const char* botan_version_string()

    Returns a free-from version string

.. cpp:function:: uint32_t botan_version_major()

    Returns the major version of the library

.. cpp:function:: uint32_t botan_version_minor()

    Returns the minor version of the library
.. cpp:function:: uint32_t botan_version_patch()

    Returns the patch version of the library

.. cpp:function:: uint32_t botan_version_datestamp()

    Returns the date this version was released as an integer, or 0
    if an unreleased version

Hash Functions
----------------------------------------

.. cpp:type:: opaque* botan_hash_t

    An opaque data type for a hash. Don't mess with it.

.. cpp:function:: botan_hash_t botan_hash_init(const char* hash, uint32_t flags)

    Creates a hash of the given name. Returns null on failure. Flags should
    always be zero in this version of the API.

.. cpp:function:: int botan_hash_destroy(botan_hash_t hash)

    Destroy the object created by botan_hash_init

.. cpp:function:: int botan_hash_clear(botan_hash_t hash)

    Reset the state of this object back to clean, as if no input has
    been supplied

.. cpp:function:: size_t botan_hash_output_length(botan_hash_t hash)

     Return the output length of the hash

.. cpp:function:: int botan_hash_update(botan_hash_t hash, const uint8_t* input, size_t len)

    Add input to the hash computation

.. cpp:function:: int botan_hash_final(botan_hash_t hash, uint8_t out[])

    Finalize the hash and place the output in out. Exactly
    botan_hash_output_length() bytes will be written.

Authentication Codes
----------------------------------------
.. cpp:type:: opaque* botan_mac_t

    An opaque data type for a MAC. Don't mess with it, but do remember
    to set a random key first.

.. cpp:function:: botan_mac_t botan_mac_init(const char* mac, uint32_t flags)

.. cpp:function:: int botan_mac_destroy(botan_mac_t mac)

.. cpp:function:: int botan_mac_clear(botan_mac_t hash)

.. cpp:function:: int botan_mac_set_key(botan_mac_t mac, const uint8_t* key, size_t key_len)

.. cpp:function:: int botan_mac_update(botan_mac_t mac, uint8_t buf[], size_t len)

.. cpp:function:: int botan_mac_final(botan_mac_t mac, uint8_t out[], size_t* out_len)

.. cpp:function:: size_t botan_mac_output_length(botan_mac_t mac)

Ciphers
----------------------------------------

.. cpp:type:: opaque* botan_cipher_t

    An opaque data type for a MAC. Don't mess with it, but do remember
    to set a random key first. And please use an AEAD.

.. cpp:function:: botan_cipher_t botan_cipher_init(const char* cipher_name, uint32_t flags)

    Create a cipher object from a name such as "AES-256/GCM" or "Serpent/OCB".

    Flags is a bitfield
    The low bit of flags specifies if encrypt or decrypt

.. cpp:function:: int botan_cipher_destroy(botan_cipher_t cipher)

.. cpp:function:: int botan_cipher_clear(botan_cipher_t hash)

.. cpp:function:: int botan_cipher_set_key(botan_cipher_t cipher, \
                  const uint8_t* key, size_t key_len)

.. cpp:function:: int botan_cipher_set_associated_data(botan_cipher_t cipher, \
                                               const uint8_t* ad, size_t ad_len)

.. cpp:function:: int botan_cipher_start(botan_cipher_t cipher, \
                                 const uint8_t* nonce, size_t nonce_len)

.. cpp:function:: int botan_cipher_is_authenticated(botan_cipher_t cipher)

.. cpp:function:: size_t botan_cipher_tag_size(botan_cipher_t cipher)

.. cpp:function:: int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl)

.. cpp:function:: size_t botan_cipher_default_nonce_length(botan_cipher_t cipher)

