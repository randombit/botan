Threshold Secret Sharing
========================================

.. versionadded:: 1.9.1

Threshold secret sharing allows splitting a secret into ``N`` shares such that
``M`` (for specified ``M`` <= ``N``) is sufficient to recover the secret, but an
attacker with ``M - 1`` shares cannot derive any information about the secret.

The implementation in Botan follows an expired Internet draft
"draft-mcgrew-tss-03". Several other implementations of this TSS format exist.

.. cpp:class:: RTSS_Share

  .. cpp:function:: static std::vector<RTSS_Share> split(uint8_t M, uint8_t N, \
               const uint8_t secret[], uint16_t secret_len, \
               const std::vector<uint8_t>& identifier, \
               const std::string& hash_fn, \
               RandomNumberGenerator& rng)

     Split a secret. The identifier is an optional key identifier which may be
     up to 16 bytes long. Shorter identifiers are padded with zeros.

     The hash function must be either "SHA-1", "SHA-256", or "None" to disable
     the checksum.

     This will return a vector of length ``N``, any ``M`` of these shares is
     sufficient to reconstruct the data.

  .. cpp:function:: static secure_vector<uint8_t> reconstruct(const std::vector<RTSS_Share>& shares)

      Given a sufficient number of shares, reconstruct a secret.

  .. cpp:function:: RTSS_Share(const uint8_t data[], size_t len)

      Read a TSS share as a sequence of bytes.

  .. cpp:function:: const secure_vector<uint8>& data() const

      Return the data of this share.

  .. cpp:function:: uint8_t share_id() const

      Return the share ID which will be in the range 1...255

