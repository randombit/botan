.. _cipher_modes:

Cipher Modes
=====================

A block cipher by itself, is only able to securely encrypt a single data block.
To be able to securely encrypt data of arbitrary length, a mode of operation
applies the block cipher's single block operation repeatedly to encrypt
an entire message.

All cipher mode implementations are are derived from the base class
:cpp:class:`Cipher_Mode`, which is declared in ``botan/cipher_mode.h``.

.. warning::
   Using an unauthenticted cipher mode without combining it with a
   :ref:`mac` is insecure. Prefer using an :ref:`aead`.

.. cpp:class:: Cipher_Mode

  .. cpp:function:: void set_key(const uint8_t* key, size_t length)

    Set the symmetric key to be used.

  .. cpp:function:: bool valid_keylength(size_t length) const

     This function returns true if and only if *length* is a valid
     keylength for the algorithm.

  .. cpp:function:: size_t minimum_keylength() const

     Return the smallest key length (in bytes) that is acceptable for the
     algorithm.

  .. cpp:function:: size_t maximum_keylength() const

     Return the largest key length (in bytes) that is acceptable for the
     algorithm.

  .. cpp:function:: size_t default_nonce_length() const

    Return the default (preferable) nonce size for this cipher mode.

  .. cpp:function:: bool valid_nonce_length(size_t nonce_len) const

    Return true if *nonce_len* is a valid length for a nonce with this
    algorithm.

  .. cpp:function:: bool authenticated() const

    Return true if this cipher mode is authenticated

  .. cpp:function:: size_t tag_size() const

    Return the length in bytes of the authentication tag this algorithm
    generates. If the mode is not authenticated, this will return 0. If the mode
    is authenticated, it will return some positive value (typically somewhere
    between 8 and 16).

  .. cpp:function:: void clear()

    Clear all internal state. The object will act exactly like one which was
    just allocated.

  .. cpp:function:: void reset()

    Reset all message state. For example if you called :cpp:func:`start_msg`,
    then :cpp:func:`process` to process some ciphertext, but then encounter an
    IO error and must abandon the current message, you can call `reset`. The
    object will retain the key (unlike calling :cpp:func:`clear` which also
    resets the key) but the nonce and current message state will be erased.

  .. cpp:function:: void start_msg(const uint8_t* nonce, size_t nonce_len)

    Set up for processing a new message. This function must be called with a new
    random value for each message. For almost all modes (excepting SIV), if the
    same nonce is ever used twice with the same key, the encryption scheme loses
    its confidentiality and/or authenticity properties.

  .. cpp:function:: void start(const std::vector<uint8_t> nonce)

    Acts like :cpp:func:`start_msg`\ (nonce.data(), nonce.size()).

  .. cpp:function:: void start(const uint8_t* nonce, size_t nonce_len)

    Acts like :cpp:func:`start_msg`\ (nonce, nonce_len).

  .. cpp:function:: virtual size_t update_granularity() const

    The :cpp:class:`Cipher_Mode` interface requires message processing in multiples of the block size.
    Returns size of required blocks to update. Will return 1 if the mode implementation
    does not require buffering.

  .. cpp:function:: virtual size_t ideal_granularity() const

    Returns a multiple of update_granularity sized for ideal performance.

    In fact this is not truly the "ideal" buffer size but just reflects the
    smallest possible buffer that can reasonably take advantage of available
    parallelism (due to SIMD execution, etc). If you are concerned about
    performance, it may be advisable to take this return value and scale it to
    approximately 4 KB, and use buffers of that size.

  .. cpp:function:: virtual size_t process(uint8_t* msg, size_t msg_len)

    Process msg in place and returns the number of bytes written. *msg* must
    be a multiple of :cpp:func:`update_granularity`.

  .. cpp:function:: void update(secure_vector<uint8_t>& buffer, size_t offset = 0)

    Continue processing a message in the buffer in place. The passed buffer's
    size must be a multiple of :cpp:func:`update_granularity`.  The first
    *offset* bytes of the buffer will be ignored.

  .. cpp:function:: size_t minimum_final_size() const

    Returns the minimum size needed for :cpp:func:`finish`. This is used for
    example when processing an AEAD message, to ensure the tag is available. In
    that case, the encryption side will return 0 (since the tag is generated,
    rather than being provided) while the decryption mode will return the size
    of the tag.

  .. cpp:function:: void finish(secure_vector<uint8_t>& final_block, size_t offset = 0)

    Finalize the message processing with a final block of at least :cpp:func:`minimum_final_size` size.
    The first *offset* bytes of the passed final block will be ignored.

.. _cipher_modes_example:

Code Example
---------------------

The following code encrypts the specified plaintext using AES-128/CBC
with PKCS#7 padding.

.. warning::
   This example ignores the requirement to authenticate the ciphertext

.. note::
   Simply replacing the string "AES-128/CBC/PKCS7" string in the example below
   with "AES-128/GCM" suffices to use authenticated encryption.

.. literalinclude:: /../src/examples/aes_cbc.cpp
   :language: cpp


Available Unauthenticated Cipher Modes
-----------------------------------------

.. note::
   CTR and OFB modes are also implemented, but these are treated as
   :cpp:class:`Stream_Cipher`\s instead.

CBC
~~~~~~~~~~~~

Available if ``BOTAN_HAS_MODE_CBC`` is defined.

CBC requires the plaintext be padded using a reversible rule. The following
padding schemes are implemented

PKCS#7 (RFC5652)
  The last byte in the padded block defines the padding length p, the remaining padding bytes are set to p as well.
ANSI X9.23
  The last byte in the padded block defines the padding length, the remaining padding is filled with 0x00.
OneAndZeros (ISO/IEC 7816-4)
  The first padding byte is set to 0x80, the remaining padding bytes are set to 0x00.
ESP (RFC 4303)
  The first padding byte is set to 0x01, the next ones to 0x02, 0x03, ... (monotonically increasing sequence).

Ciphertext stealing (CTS) is also implemented. This scheme allows the
ciphertext to have the same length as the plaintext, however using CTS
requires the input be at least one full block plus one byte. It is
also less commonly implemented.

.. warning::
   Using CBC with padding without an authentication mode exposes your
   application to CBC padding oracle attacks, which allow recovering
   the plaintext of arbitrary messages. Always pair CBC with a MAC such
   as HMAC (or, preferably, use an AEAD such as GCM).

Algorithm specification name:
``<BlockCipher>/CBC/<optional padding scheme>`` (reported name) /
``CBC(<BlockCipher>,<optional padding scheme>)``

- Available padding schemes:

  - ``NoPadding``
  - ``PKCS7`` (default)
  - ``OneAndZeros``
  - ``X9.23``
  - ``ESP``
  - ``CTS``

- Examples: ``AES-128/CBC/PKCS7``, ``AES-256/CBC``

CFB
~~~~~~~~~~~~

Available if ``BOTAN_HAS_MODE_CFB`` is defined.

CFB uses a block cipher to create a self-synchronizing stream cipher. It is used
for example in the OpenPGP protocol. There is no reason to prefer it, as it has
worse performance characteristics than modes such as CTR or CBC.

Algorithm specification name:
``<BlockCipher>/CFB(<optional feedback bits>)`` (reported name) /
``CFB(<BlockCipher>,<optional feedback bits>)``

- Feedback bits defaults to the size of the underlying block cipher.
- Examples: ``AES-192/CFB``, ``AES-128/CFB(8)``

XTS
~~~~~~~~~

Available if ``BOTAN_HAS_MODE_XTS`` is defined.

XTS is a mode specialized for encrypting disk or database storage
where ciphertext expansion is not possible. XTS requires all inputs be
at least one full block (16 bytes for AES), however for any acceptable
input length, there is no ciphertext expansion.

Algorithm specification name:
``<BlockCipher>/XTS`` (reported name) / ``XTS(<BlockCipher>)``,
e.g. ``AES-256/XTS``

.. _aead:

AEAD Mode
---------------------------

AEAD (Authenticated Encryption with Associated Data) modes provide message
encryption, message authentication, and the ability to authenticate additional
data that is not included in the ciphertext (such as a sequence number or
header). It is a subclass of :cpp:class:`Cipher_Mode`.

.. cpp:class:: AEAD_Mode

  .. cpp:function:: void set_key(const SymmetricKey& key)

       Set the key

  .. cpp:function:: Key_Length_Specification key_spec() const

       Return the key length specification

  .. cpp:function:: void set_associated_data(const uint8_t ad[], size_t ad_len)

       Set any associated data for this message. For maximum portability between
       different modes, this must be called after :cpp:func:`set_key` and before
       :cpp:func:`start`.

       If the associated data does not change, it is not necessary to call this
       function more than once, even across multiple calls to :cpp:func:`start`
       and :cpp:func:`finish`.

  .. cpp:function:: void start(const uint8_t nonce[], size_t nonce_len)

       Start processing a message, using *nonce* as the unique per-message
       value. It does not need to be random, simply unique (per key).

       .. warning::
          With almost all AEADs, if the same nonce is ever used to encrypt two
          different messages under the same key, all security is lost. If
          reliably generating unique nonces is difficult in your environment,
          use SIV mode which retains security even if nonces are repeated.

  .. cpp:function:: void update(secure_vector<uint8_t>& buffer, size_t offset = 0)

       Continue processing a message. The *buffer* is an in/out parameter and
       may be resized. In particular, some modes require that all input be
       consumed before any output is produced; with these modes, *buffer* will
       be returned empty.

       On input, the buffer must be sized in blocks of size
       :cpp:func:`update_granularity`. For instance if the update granularity
       was 64, then *buffer* could be 64, 128, 192, ... bytes.

       The first *offset* bytes of *buffer* will be ignored (this allows in
       place processing of a buffer that contains an initial plaintext header)

  .. cpp:function:: void finish(secure_vector<uint8_t>& buffer, size_t offset = 0)

       Complete processing a message with a final input of *buffer*, which is
       treated the same as with :cpp:func:`update`. It must contain at least
       :cpp:func:`final_minimum_size` bytes.

       Note that if you have the entire message in hand, calling finish without
       ever calling update is both efficient and convenient.

       .. note::

          During decryption, if the supplied authentication tag does not
          validate, finish will throw an instance of Invalid_Authentication_Tag
          (aka Integrity_Failure, which was the name for this exception in
          versions before 2.10, a typedef is included for compatability).

          If this occurs, all plaintext previously output via calls to update
          must be destroyed and not used in any way that an attacker could
          observe the effects of. This could be anything from echoing the
          plaintext back (perhaps in an error message), or by making an external
          RPC whose destination or contents depend on the plaintext. The only
          thing you can do is buffer it, and in the event of an invalid tag,
          erase the previously decrypted content from memory.

          One simply way to assure this could never happen is to never
          call update, and instead always marshal the entire message
          into a single buffer and call finish on it when decrypting.

  .. cpp:function:: size_t update_granularity() const

       The AEAD interface requires :cpp:func:`update` be called with blocks of
       this size. This will be 1, if the mode can process any length inputs.

  .. cpp:function:: size_t final_minimum_size() const

       The AEAD interface requires :cpp:func:`finish` be called with at least
       this many bytes (which may be zero, or greater than
       :cpp:func:`update_granularity`)

  .. cpp:function:: bool valid_nonce_length(size_t nonce_len) const

       Returns true if *nonce_len* is a valid nonce length for this scheme. For
       EAX and GCM, any length nonces are allowed. OCB allows any value between
       8 and 15 bytes.

  .. cpp:function:: size_t default_nonce_length() const

       Returns a reasonable length for the nonce, typically either 96
       bits, or the only supported length for modes which don't
       support 96 bit nonces.


Available AEAD Modes
-------------------------

If in doubt about what to use, pick ChaCha20Poly1305, AES-256/GCM, or AES-256/SIV.
Both ChaCha20Poly1305 and AES with GCM are widely implemented. SIV is somewhat
more obscure (and is slower than either GCM or ChaCha20Poly1305), but has
excellent security properties.

CCM
~~~~~

Available if ``BOTAN_HAS_AEAD_CCM`` is defined.

A composition of CTR mode and CBC-MAC. Requires a 128-bit block cipher. This is
a NIST standard mode, but that is about all to recommend it. Prefer EAX.

Algorithm specification name:
``<BlockCipher>/CCM(<optional tag size>,<optional L>)`` (reported name) /
``CCM(<BlockCipher>,<optional tag size>,<optional L>)``

- Tag size defaults to 16.
- L defaults to 3.
- Examples: ``AES-128/CCM``, ``AES-128/CCM(8)``, ``AES-128/CCM(8,2)``

ChaCha20Poly1305
~~~~~~~~~~~~~~~~~~

Available if ``BOTAN_HAS_AEAD_CHACHA20_POLY1305`` is defined.

Unlike the other AEADs which are based on block ciphers, this mode is based on
the ChaCha stream cipher and the Poly1305 authentication code. It is very fast
on all modern platforms.

ChaCha20Poly1305 supports 64-bit, 96-bit, and (since 2.8) 192-bit nonces. 64-bit nonces
are the "classic" ChaCha20Poly1305 design. 96-bit nonces are used by the IETF standard
version of ChaCha20Poly1305. And 192-bit nonces is the XChaCha20Poly1305 construction,
which is somewhat less common.

For best interop use the IETF version with 96-bit nonces. However 96 bits is small enough
that it can be dangerous to generate nonces randomly if more than ~ 2^32 messages are
encrypted under a single key, since if a nonce is ever reused ChaCha20Poly1305 becomes
insecure. It is better to use a counter for the nonce in this case.

If you are encrypting many messages under a single key and cannot maintain a counter for
the nonce, prefer XChaCha20Poly1305 since a 192 bit nonce is large enough that randomly
chosen nonces are extremely unlikely to repeat.

Algorithm specification name: ``ChaCha20Poly1305``

EAX
~~~~~

Available if ``BOTAN_HAS_AEAD_EAX`` is defined.

A secure composition of CTR mode and CMAC. Supports 128-bit, 256-bit and 512-bit
block ciphers.

Algorithm specification name:
``<BlockCipher>/EAX(<optional tag size>)`` /
``EAX(<BlockCipher>,<optional tag size>)``

- Tag size defaults to 16.
- Reports name as ``<BlockCipher>/EAX``, i.e. without the tag size.
- Examples: e.g. ``AES-128/EAX``, ``AES-128/EAX(8)``

GCM
~~~~~

Available if ``BOTAN_HAS_AEAD_GCM`` is defined.

NIST standard, commonly used. Requires a 128-bit block cipher. Fairly slow,
unless hardware support for carryless multiplies is available.

Algorithm specification name:
``<BlockCipher>/GCM(<optional tag size>)`` (reported name) /
``GCM(<BlockCipher>,<optional tag size>)``

- Tag size defaults to 16.
- Examples: e.g. ``AES-128/GCM``, ``AES-128/GCM(12)``

OCB
~~~~~

Available if ``BOTAN_HAS_AEAD_OCB`` is defined.

A block cipher based AEAD. Supports 128-bit, 256-bit and 512-bit block ciphers.
This mode is very fast and easily secured against side channels. Adoption has
been poor because until 2021 it was patented in the United States. The patent
was allowed to lapse in early 2021.

Algorithm specification name:
``<BlockCipher>/OCB(<optional tag size>)`` /
``OCB(<BlockCipher>,<optional tag size>)``

- Tag size defaults to 16.
- Reports name as ``<BlockCipher>/OCB``, i.e. without the tag size.
- Examples: e.g. ``AES-128/OCB``, ``AES-128/OCB(12)``

SIV
~~~~~~

Available if ``BOTAN_HAS_AEAD_SIV`` is defined.

Requires a 128-bit block cipher. Unlike other AEADs, SIV is "misuse resistant";
if a nonce is repeated, SIV retains security, with the exception that if the
same nonce is used to encrypt the same message multiple times, an attacker can
detect the fact that the message was duplicated (this is simply because if both
the nonce and the message are reused, SIV will output identical ciphertexts).

Algorithm specification name:
``<BlockCipher>/SIV`` (reported name) / ``SIV(<BlockCipher>)``,
e.g. ``AES-128/SIV``
