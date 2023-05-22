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

API Overview
------------

.. container:: toggle

   .. doxygenclass:: Botan::Cipher_Mode
      :members: create,create_or_throw,set_key,minimum_keylength,maximum_keylength,default_nonce_length,authenticated,tag_size,start,update_granularity,ideal_granularity,requires_entire_message,process,update,finish

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

Ciphertext stealing (CTS) is also implemented. This scheme allows the
ciphertext to have the same length as the plaintext, however using CTS
requires the input be at least one full block plus one byte. It is
also less commonly implemented.

.. warning::
   Using CBC with padding without an authentication mode exposes your
   application to CBC padding oracle attacks, which allow recovering
   the plaintext of arbitrary messages. Always pair CBC with a MAC such
   as HMAC (or, preferably, use an AEAD such as GCM).

CFB
~~~~~~~~~~~~

Available if ``BOTAN_HAS_MODE_CFB`` is defined.

CFB uses a block cipher to create a self-synchronizing stream cipher. It is used
for example in the OpenPGP protocol. There is no reason to prefer it, as it has
worse performance characteristics than modes such as CTR or CBC.

XTS
~~~~~~~~~

Available if ``BOTAN_HAS_MODE_XTS`` is defined.

XTS is a mode specialized for encrypting disk or database storage
where ciphertext expansion is not possible. XTS requires all inputs be
at least one full block (16 bytes for AES), however for any acceptable
input length, there is no ciphertext expansion.

.. _aead:

AEAD Mode
---------------------------

AEAD (Authenticated Encryption with Associated Data) modes provide message
encryption, message authentication, and the ability to authenticate additional
data that is not included in the ciphertext (such as a sequence number or
header). It is a subclass of :cpp:class:`Cipher_Mode`.

API Overview
~~~~~~~~~~~~

.. container:: toggle

   .. doxygenclass:: Botan::AEAD_Mode
      :members: create,create_or_throw,set_associated_data,set_associated_data_n,final_minimum_size,maximum_associated_data_inputs

Available AEAD Modes
-------------------------

If in doubt about what to use, pick ChaCha20Poly1305, AES-256/GCM, or AES-256/SIV.
Both ChaCha20Poly1305 and AES with GCM are widely implemented. SIV is somewhat
more obscure (and is slower than either GCM or ChaCha20Poly1305), but has
excellent security properties.

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
been poor because until 2021 it was patented in the United States. The patent
was allowed to lapse in early 2021.

EAX
~~~~~

Available if ``BOTAN_HAS_AEAD_EAX`` is defined.

A secure composition of CTR mode and CMAC. Supports 128-bit, 256-bit and 512-bit
block ciphers.

SIV
~~~~~~

Available if ``BOTAN_HAS_AEAD_SIV`` is defined.

Requires a 128-bit block cipher. Unlike other AEADs, SIV is "misuse resistant";
if a nonce is repeated, SIV retains security, with the exception that if the
same nonce is used to encrypt the same message multiple times, an attacker can
detect the fact that the message was duplicated (this is simply because if both
the nonce and the message are reused, SIV will output identical ciphertexts).

CCM
~~~~~

Available if ``BOTAN_HAS_AEAD_CCM`` is defined.

A composition of CTR mode and CBC-MAC. Requires a 128-bit block cipher. This is
a NIST standard mode, but that is about all to recommend it. Prefer EAX.
