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

     Return the smallest key length (in bytes) that is acceptible for the
     algorithm.

  .. cpp:function:: size_t maximum_keylength() const

     Return the largest key length (in bytes) that is acceptible for the
     algorithm.

  .. cpp:function:: void start_msg(const uint8_t* nonce, size_t nonce_len)

    Set the IV (unique per-message nonce) of the mode of operation and prepare for message processing.

  .. cpp:function:: void start(const std::vector<uint8_t> nonce)

    Acts like :cpp:func:`start_msg`\ (nonce.data(), nonce.size()).

  .. cpp:function:: void start(const uint8_t* nonce, size_t nonce_len)

    Acts like :cpp:func:`start_msg`\ (nonce, nonce_len).

  .. cpp:function:: virtual size_t update_granularity() const

    The :cpp:class:`Cipher_Mode` interface requires message processing in multiples of the block size.
    Returns size of required blocks to update and 1, if the mode can process messages of any length.

  .. cpp:function:: virtual size_t process(uint8_t* msg, size_t msg_len)

    Process msg in place and returns bytes written. msg must be a multiple of :cpp:func:`update_granularity`.

  .. cpp:function:: void update(secure_vector<uint8_t>& buffer, size_t offset = 0)

    Continue processing a message in the buffer in place. The passed buffer's size must be a multiple of :cpp:func:`update_granularity`.
    The first *offset* bytes of the buffer will be ignored.

  .. cpp:function:: size_t minimum_final_size() const

    Returns the minimum size needed for :cpp:func:`finish`.

  .. cpp:function:: void finish(secure_vector<uint8_t>& final_block, size_t offset = 0)

    Finalize the message processing with a final block of at least :cpp:func:`minimum_final_size` size.
    The first *offset* bytes of the passed final block will be ignored.

Code Example
---------------------

The following code encrypts the specified plaintext using AES-128/CBC
with PKCS#7 padding.

.. warning::
   This example ignores the requirement to authenticate the ciphertext

.. note::
   Simply replacing the string "AES-128/CBC/PKCS7" string in the example below
   with "AES-128/GCM" suffices to use authenticated encryption.

.. code-block:: cpp

    #include <botan/rng.h>
    #include <botan/auto_rng.h>
    #include <botan/cipher_mode.h>
    #include <botan/hex.h>
    #include <iostream>

    int main()
       {
       Botan::AutoSeeded_RNG rng;

       const std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
       const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

       std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION);
       enc->set_key(key);

       //generate fresh nonce (IV)
       Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

       // Copy input data to a buffer that will be encrypted
       Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data()+plaintext.length());

       enc->start(iv);
       enc->finish(pt);

       std::cout << enc->name() << " with iv " << Botan::hex_encode(iv) << " " << Botan::hex_encode(pt) << "\n";
       return 0;
       }


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

CFB
~~~~~~~~~~~~

Available if ``BOTAN_HAS_MODE_CFB`` is defined.

CFB uses a block cipher to create a self-syncronizing stream cipher. It is used
for example in the OpenPGP protocol. There is no reason to prefer it.

XTS
~~~~~~~~~

Available if ``BOTAN_HAS_MODE_XTS`` is defined.

XTS is a mode specialized for encrypting disk storage. XTS requires all inputs
be at least 1 byte longer than the native block size of the cipher.

.. _aead:

AEAD Mode
---------------------------

AEAD (Authenticated Encryption with Associated Data) modes provide message
encryption, message authentication, and the ability to authenticate additional
data that is not included in the ciphertext (such as a sequence number or
header). It is a subclass of :cpp:class:`Cipher_Mode`.

The AEAD interface can be used directly, or as part of the filter system by
using :cpp:class:`AEAD_Filter` (a subclass of :cpp:class:`Keyed_Filter` which
will be returned by :cpp:func:`get_cipher` if the named cipher is an AEAD mode).

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
          During decryption, finish will throw an instance of Integrity_Failure
          if the MAC does not validate. If this occurs, all plaintext previously
          output via calls to update must be destroyed and not used in any
          way that an attacker could observe the effects of.

          One simply way to assure this could never happen is to never
          call update, and instead always marshall the entire message
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

ChaCha20Poly1305
~~~~~~~~~~~~~~~~~~

Available if ``BOTAN_HAS_AEAD_CHACHA20_POLY1305`` is defined.

Unlike the other AEADs which are based on block ciphers, this mode is based on
the ChaCha stream cipher and the Poly1305 authentication code. It is very fast
on all modern platforms.

GCM
~~~~~

Available if ``BOTAN_HAS_AEAD_GCM`` is defined.

NIST standard, commonly used. Requires a 128-bit block cipher. Fairly slow,
unless hardware support for carryless multiplies is available.

OCB
~~~~~

Available if ``BOTAN_HAS_AEAD_OCB`` is defined.

A block cipher based AEAD. Supports 128-bit, 256-bit and 512-bit block ciphers.
This mode is very fast and easily secured against side channels. Adoption has
been poor because it is patented in the United States, though a license is
available allowing it to be freely used by open source software.

EAX
~~~~~

Available if ``BOTAN_HAS_AEAD_EAX`` is defined.

A secure composition of CTR mode and CMAC. Supports 128-bit, 256-bit and 512-bit
block ciphers.

SIV
~~~~~~

Available if ``BOTAN_HAS_AEAD_SIV`` is defined.

Requires a 128-bit block cipher. Unlike other AEADs, SIV is "misuse resistent";
if a nonce is repeated, SIV retains security, with the exception that if the
same nonce is used to encrypt the same message multiple times, an attacker can
detect the fact that the message was duplicated (this is simply because if both
the nonce and the message are reused, SIV will output identical ciphertexts).

CCM
~~~~~

Available if ``BOTAN_HAS_AEAD_CCM`` is defined.

A composition of CTR mode and CBC-MAC. Requires a 128-bit block cipher. This is
a NIST standard mode, but that is about all to recommend it. Prefer EAX.
