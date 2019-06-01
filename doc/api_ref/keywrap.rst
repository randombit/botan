AES Key Wrapping
=================================

NIST specifies two mechanisms for wrapping (encrypting) symmetric keys using
another key. The first (and older, more widely supported) method requires the
input be a multiple of 8 bytes long. The other allows any length input, though
only up to 2**32 bytes.

These algorithms are described in NIST SP 800-38F, and RFCs 3394 and 5649.

This API, defined in ``nist_keywrap.h``, first became available in version 2.4.0

These functions take an arbitrary 128-bit block cipher object, which must
already have been keyed with the key encryption key. NIST only allows these
functions with AES, but any 128-bit cipher will do and some other implementations
(such as in OpenSSL) do also allow other ciphers.  Use AES for best interop.

.. cpp:function:: std::vector<uint8_t> nist_key_wrap(const uint8_t input[], \
                  size_t input_len, const BlockCipher& bc)

   This performs KW (key wrap) mode. The input must be a multiple of 8 bytes long.

.. cpp:function:: secure_vector<uint8_t> nist_key_unwrap(const uint8_t input[], \
                  size_t input_len,  const BlockCipher& bc)

   This unwraps the result of nist_key_wrap, or throw Invalid_Authentication_Tag on error.

.. cpp:function:: std::vector<uint8_t> nist_key_wrap_padded(const uint8_t input[], \
                  size_t input_len, const BlockCipher& bc)

   This performs KWP (key wrap with padding) mode. The input can be any length.

.. cpp:function:: secure_vector<uint8_t> nist_key_unwrap_padded(const uint8_t input[], \
                  size_t input_len, const BlockCipher& bc)

   This unwraps the result of nist_key_wrap_padded, or throws Invalid_Authentication_Tag
   on error.

RFC 3394 Interface
-----------------------------

This is an older interface that was first available (with slight changes) in
1.10, and available in its current form since 2.0 release. It uses a 128-bit,
192-bit, or 256-bit key to encrypt an input key. AES is always used. The input
must be a multiple of 8 bytes; if not an exception is thrown.

This interface is defined in ``rfc3394.h``.

.. cpp:function:: secure_vector<uint8_t> rfc3394_keywrap(const secure_vector<uint8_t>& key, \
                                                         const SymmetricKey& kek)

  Wrap the input key using kek (the key encryption key), and return the result. It will
  be 8 bytes longer than the input key.

.. cpp:function:: secure_vector<uint8_t> rfc3394_keyunwrap(const secure_vector<uint8_t>& key, \
                                                           const SymmetricKey& kek)

  Unwrap a key wrapped with rfc3394_keywrap.


