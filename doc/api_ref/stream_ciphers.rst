Stream Ciphers
========================

In contrast to block ciphers, stream ciphers operate on a plaintext stream
instead of blocks. Thus encrypting data results in changing the internal state
of the cipher and encryption of plaintext with arbitrary length is possible in
one go (in byte amounts). All implemented stream ciphers derive from the base
class :cpp:class:`StreamCipher` (`botan/stream_cipher.h`).

.. warning::

   Using a stream cipher without an authentication code is extremely insecure,
   because an attacker can trivially modify messages. Prefer using an
   authenticated cipher mode such as GCM or SIV.

.. warning::

   Encrypting more than one message with the same key requires careful management
   of initialization vectors. Otherwise the keystream will be reused, which causes
   the security of the cipher to completely fail.

Code Example
-----------------

The following code encrypts a provided plaintext using ChaCha20.

.. literalinclude:: /../src/examples/chacha.cpp
   :language: cpp

API Overview
------------

.. doxygenclass:: Botan::StreamCipher
   :members: create,create_or_throw,set_key,minimum_keylength,maximum_keylength,default_iv_length,set_iv,seek,cipher,cipher1,encipher,encrypt,decrypt,keystream_bytes, write_keystream

Available Stream Ciphers
----------------------------

Botan provides the following stream ciphers. If in doubt, pick ChaCha20 or CTR(AES-256).

CTR-BE
~~~~~~~

Counter mode converts a block cipher into a stream cipher. It offers
parallel execution and can seek within the output stream, both useful
properties.

CTR mode requires a nonce, which can be any length up to the block size of the
underlying cipher. If it is shorter than the block size, sufficient zero bytes
are appended.

It is possible to choose the width of the counter portion, which can improve
performance somewhat, but limits the maximum number of bytes that can safely be
encrypted. Different protocols have different conventions for the width of the
counter portion. This is done by specifying the width (which must be at least 4
bytes, allowing to encrypt 2\ :sup:`32` blocks of data) for example using
"CTR(AES-256,8)" will select a 64-bit (8 byte) counter.

(The ``-BE`` suffix refers to big-endian convention for the counter.
Little-endian counter mode is rarely used and not currently implemented.)

OFB
~~~~~

Another stream cipher based on a block cipher. Unlike CTR mode, it does not
allow parallel execution or seeking within the output stream. Prefer CTR.

Available if ``BOTAN_HAS_OFB`` is defined.

ChaCha
~~~~~~~~

A very fast cipher, now widely deployed in TLS as part of the ChaCha20Poly1305
AEAD. Can be used with 8 (fast but dangerous), 12 (balance), or 20 rounds
(conservative). Even with 20 rounds, ChaCha is very fast. Use 20 rounds.

ChaCha supports an optional IV (which defaults to all zeros). It can be of
length 64, 96 or (since 2.8) 192 bits. Using ChaCha with a 192 bit nonce is also
known as XChaCha.

Available if ``BOTAN_HAS_CHACHA`` is defined.

Salsa20
~~~~~~~~~

An earlier iteration of the ChaCha design, this cipher is popular due to its use
in the libsodium library. Prefer ChaCha.

Salsa supports an optional IV (which defaults to all zeros). It can be of length
64 or 192 bits. Using Salsa with a 192 bit nonce is also known as XSalsa.

Available if ``BOTAN_HAS_SALSA20`` is defined.

SHAKE-128
~~~~~~~~~~~~

This is the SHAKE-128 XOF exposed as a stream cipher. It is slower than ChaCha
and somewhat obscure. It does not support IVs or seeking within the cipher
stream.

Available if ``BOTAN_HAS_SHAKE_CIPHER`` is defined.

RC4
~~~~

An old and very widely deployed stream cipher notable for its simplicity. It
does not support IVs or seeking within the cipher stream. Compared to modern
algorithms like ChaCha20, it is also quite slow.

.. warning::

   RC4 is prone to numerous attacks. **Avoid in new code** and use only if
   required for compatibility with existing systems.

Available if ``BOTAN_HAS_RC4`` is defined.
