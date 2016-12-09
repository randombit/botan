.. _symmetric_crypto:

Symmetric Key Cryptography
===========================================
Block ciphers, stream ciphers and MACs are all keyed operations.
They require a particular key, which is a chosen, sampled or computed
string of bits of a specified length. The length required by any particular algorithm
may vary, depending on both the algorithm specification and the implementation.
You can query any Botan object to find out what key length(s) it supports.

To make this similarity in terms of keying explicit, all algorithms of
those types are derived from the :cpp:class:`SymmetricAlgorithm` base.
This type provides functions for setting the key, and querying
restrictions on the size of the key.

.. cpp:class:: SymmetricAlgorithm

   .. cpp:function:: void set_key(const byte* key, size_t length)

   .. cpp:function:: void set_key(const SymmetricKey& key)

     This sets the key to the value specified. Most algorithms only
     accept keys of certain lengths. If you attempt to call
     ``set_key`` with a key length that is not supported, the
     exception ``Invalid_Key_Length`` will be thrown.

     In all cases, ``set_key`` must be called on an object before any
     data processing (encryption, decryption, etc) is done by that
     object. If this is not done, the results are undefined.

   .. cpp:function:: bool valid_keylength(size_t length) const

     This function returns true if and only if *length* is a valid
     keylength for the algorithm.

   .. cpp:function:: size_t minimum_keylength() const

     Return the smallest key length (in bytes) that is acceptible for the
     algorithm.

   .. cpp:function:: size_t maximum_keylength() const

     Return the largest key length (in bytes) that is acceptible for the
     algorithm.

Block Ciphers
---------------------------------
A block cipher is a deterministic symmetric encryption algorithm, which
encrypts data of a fixed length, called block size. All block ciphers classes
in Botan are subclasses of :cpp:class:`BlockCipher` defined in `botan/block_cipher.h`.
As a symmetrically keyed algorithm, it subclasses the :cpp:class:`SymmetricAlgorithm` interface.
Note that a block cipher by itself is only secure for plaintext with the length of a single block.
When processing data larger than a single block, a block cipher mode should be used for data processing.

.. cpp:class:: BlockCipher

  .. cpp:function:: size_t block_size() const

    Returns the block size of the cipher in bytes.

  .. cpp:function:: void encrypt_n(const byte* in, \
       byte* out, size_t n) const

    Encrypt *n* blocks of data, taking the input from the array *in*
    and placing the ciphertext into *out*. The two pointers may be
    identical, but should not overlap ranges.

  .. cpp:function:: void encrypt(const byte* in, byte* out) const

    Encrypt a single block, taking the input from *in* and placing
    it in *out*. Acts like :cpp:func:`encrypt_n`\ (in, out, 1).

  .. cpp:function:: void encrypt(const std::vector<byte> in, std::vector<byte> out) const

    Encrypt a single or multiple full blocks, taking the input from *in* and placing it in *out*.
    Acts like :cpp:func:`encrypt_n`\ (in.data(), out.data(), in.size()/ block_size()).

  .. cpp:function:: void encrypt(std::vector<byte> inout) const

    Encrypt a single or multiple full blocks in place.
    Acts like :cpp:func:`encrypt_n`\ (inout.data(), inout.data(), inout.size()/ block_size()).

  .. cpp:function:: void encrypt(byte* block) const

    Identical to :cpp:func:`encrypt`\ (block, block)

  .. cpp:function:: void decrypt_n(const byte* in, byte out, size_t n) const

    Decrypt *n* blocks of data, taking the input from *in* and
    placing the plaintext in *out*. The two pointers may be
    identical, but should not overlap ranges.

  .. cpp:function:: void decrypt(const byte* in, byte* out) const

    Decrypt a single block, taking the input from *in* and placing it
    in *out*. Acts like :cpp:func:`decrypt_n`\ (in, out, 1).

  .. cpp:function:: void decrypt(const std::vector<byte> in, std::vector<byte> out) const

    Decrypt a single or multiple full blocks, taking the input from *in* and placing it in *out*.
    Acts like :cpp:func:`decrypt_n`\ (in.data(), out.data(), in.size()/ block_size()).

  .. cpp:function:: void decrypt(std::vector<byte> inout) const

    Decrypt a single or multiple full blocks in place.
    Acts like :cpp:func:`decrypt_n`\ (inout.data(), inout.data(), inout.size()/ block_size()).

  .. cpp:function:: void decrypt(byte* block) const

    Identical to :cpp:func:`decrypt`\ (block, block)

  .. cpp:function:: size_t parallelism() const

    Returns the native parallelism of this implementation, ie how
    many blocks can be processed in parallel if sufficient data is
    passed to :cpp:func:`encrypt_n` or :cpp:func:`decrypt_n`.

The following block ciphers are implemented in Botan:

#. AES (AES-128, AES-192, AES-256)
#. Serpent
#. Twofish
#. Threefish-512
#. Blowfish
#. Camellia (Camellia-128, Camellia-192, Camellia-256)
#. DES
#. 3DES
#. DESX
#. Noekeon
#. CAST (CAST-128, CAST-256)
#. IDEA
#. Kasumi
#. MISTY1
#. SEED
#. XTEA
#. GOST-28147-89
#. Cascade
#. Lion

Code Example
"""""""""""""""
For sheer demonstrative purposes, the following code encrypts a provided single block of
plaintext with AES-256 using two different keys.

.. code-block:: cpp

    #include <botan/block_cipher.h>
    #include <botan/hex.h>
    #include <iostream>
    int main ()
       {
       std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
       std::vector<uint8_t> block = Botan::hex_decode("00112233445566778899AABBCCDDEEFF");
       std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create("AES-256"));
       cipher->set_key(key);
       cipher->encrypt(block);
       std::cout << std::endl <<cipher->name() << "single block encrypt: " << Botan::hex_encode(block);

       //clear cipher for 2nd encryption with other key
       cipher->clear();
       key = Botan::hex_decode("1337133713371337133713371337133713371337133713371337133713371337");
       cipher->set_key(key);
       cipher->encrypt(block);

       std::cout << std::endl << cipher->name() << "single block encrypt: " << Botan::hex_encode(block);
       return 0;
       }

Modes of Operation
---------------------------
A block cipher by itself, is only able to securely encrypt a single data block.
To be able to securely encrypt data of arbitrary length, a mode of operation applies
the block cipher's single block operation repeatedly on a padded plaintext.
Botan implements the following block cipher padding schemes

PKCS#7 [RFC5652]
  The last byte in the padded block defines the padding length p, the remaining padding bytes are set to p as well.
ANSI X9.23
  The last byte in the padded block defines the padding length, the remaining padding is filled with 0x00.
ISO/IEC 7816-4
  The first padding byte is set to 0x80, the remaining padding bytes are set to 0x00.

and offers the following unauthenticated modes of operation:

#. ECB (Electronic Codebook Mode)
#. CBC (Cipher Block Chaining Mode)
#. CFB (Cipher Feedback Mode)
#. XTS (XEX-based tweaked-codebook mode with ciphertext stealing)
#. OFB (Output Feedback Mode)
#. CTR (Counter Mode)

The classes :cpp:class:`ECB_Mode`, :cpp:class:`CBC_Mode`, :cpp:class:`CFB_Mode` and :cpp:class:`XTS_Mode` are
are derived from the base class :cpp:class:`Cipher_Mode`, which is declared in ``botan/cipher_mode.h``.

.. cpp:class:: Cipher_Mode

  .. cpp:function:: void set_key(const SymmetricKey& key)
  .. cpp:function:: void set_key(const byte* key, size_t length)

    Set the symmetric key to be used.

  .. cpp:function:: void start_msg(const byte* nonce, size_t nonce_len)

    Set the IV (unique per-message nonce) of the mode of operation and prepare for message processing.

  .. cpp:function:: void start(const std::vector<byte> nonce)

    Acts like :cpp:func:`start_msg`\ (nonce.data(), nonce.size()).

  .. cpp:function:: void start(const byte* nonce, size_t nonce_len)

    Acts like :cpp:func:`start_msg`\ (nonce, nonce_len).

  .. cpp:function:: virtual size_t update_granularity() const

    The :cpp:class:`Cipher_Mode` interface requires message processing in multiples of the block size.
    Returns size of required blocks to update and 1, if the mode can process messages of any length.

  .. cpp:function:: virtual size_t process(byte* msg, size_t msg_len)

    Process msg in place and returns bytes written. msg must be a multiple of :cpp:func:`update_granularity`.

  .. cpp:function:: void update(secure_vector<byte>& buffer, size_t offset = 0)

    Continue processing a message in the buffer in place. The passed buffer's size must be a multiple of :cpp:func:`update_granularity`.
    The first *offset* bytes of the buffer will be ignored.

  .. cpp:function:: size_t minimum_final_size() const

    Returns the minimum size needed for :cpp:func:`finish`.

  .. cpp:function:: void finish(secure_vector<byte>& final_block, size_t offset = 0)

    Finalize the message processing with a final block of at least :cpp:func:`minimum_final_size` size.
    The first *offset* bytes of the passed final block will be ignored.

Note that :cpp:class:`CTR_BE` and :cpp:class:`OFB` are derived from the base class :cpp:class:`StreamCipher` and thus act like a stream cipher.
The class :cpp:class:`StreamCipher` is described in the respective section.


Code Example
"""""""""""""""""""""
The following code encrypts the specified plaintext using AES-128/CBC with PKCS#7 padding.

.. code-block:: cpp

    #include <botan/rng.h>
    #include <botan/auto_rng.h>
    #include <botan/cipher_mode.h>
    #include <botan/hex.h>
    #include <iostream>

    int main()
       {
       std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
       Botan::secure_vector<uint8_t> pt(plaintext.data(),plaintext.data()+plaintext.length());
    	 const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
    	 std::unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode("AES-128/CBC/PKCS7", Botan::ENCRYPTION));
    	 enc->set_key(key);

    	 //generate fresh nonce (IV)
       std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
       std::vector<uint8_t> iv(enc->default_nonce_length());
       rng->randomize(iv.data(),iv.size());
       enc->start(iv);
       enc->finish(pt);
       std::cout << std::endl << enc->name() << " with iv " << Botan::hex_encode(iv) << std::endl << Botan::hex_encode(pt);
       return 0;
       }


AEAD Modes of Operation
---------------------------

.. versionadded:: 1.11.3

AEAD (Authenticated Encryption with Associated Data) modes provide message
encryption, message authentication, and the ability to authenticate additional
data that is not included in the ciphertext (such as a sequence number or
header). It is a subclass of :cpp:class:`Symmetric_Algorithm`.

The AEAD interface can be used directly, or as part of the filter system by
using :cpp:class:`AEAD_Filter` (a subclass of :cpp:class:`Keyed_Filter` which
will be returned by :cpp:func:`get_cipher` if the named cipher is an AEAD mode).

AEAD modes currently available include GCM, OCB, EAX, SIV and CCM. All
support a 128-bit block cipher such as AES. EAX and SIV also support
256 and 512 bit block ciphers.

.. cpp:class:: AEAD_Mode

  .. cpp:function:: void set_key(const SymmetricKey& key)

       Set the key

  .. cpp:function:: Key_Length_Specification key_spec() const

       Return the key length specification

  .. cpp:function:: void set_associated_data(const byte ad[], size_t ad_len)

       Set any associated data for this message. For maximum portability between
       different modes, this must be called after :cpp:func:`set_key` and before
       :cpp:func:`start`.

       If the associated data does not change, it is not necessary to call this
       function more than once, even across multiple calls to :cpp:func:`start`
       and :cpp:func:`finish`.

  .. cpp:function:: void start(const byte nonce[], size_t nonce_len)

       Start processing a message, using *nonce* as the unique per-message
       value.

  .. cpp:function:: void update(secure_vector<byte>& buffer, size_t offset = 0)

       Continue processing a message. The *buffer* is an in/out parameter and
       may be resized. In particular, some modes require that all input be
       consumed before any output is produced; with these modes, *buffer* will
       be returned empty.

       On input, the buffer must be sized in blocks of size
       :cpp:func:`update_granularity`. For instance if the update granularity
       was 64, then *buffer* could be 64, 128, 192, ... bytes.

       The first *offset* bytes of *buffer* will be ignored (this allows in
       place processing of a buffer that contains an initial plaintext header)

  .. cpp:function:: void finish(secure_vector<byte>& buffer, size_t offset = 0)

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

Stream Ciphers
---------------------------------
In contrast to block ciphers, stream ciphers operate on a plaintext stream instead
of blocks. Thus encrypting data results in changing the internal state of the
cipher and encryption of plaintext with arbitrary length is possible in one go (in byte
amounts). All implemented stream ciphers derive from the base class :cpp:class:`StreamCipher` (`botan/stream_cipher.h`), which
implements the :cpp:class:`SymmetricAlgorithm` interface. Note that some of the implemented
stream ciphers require a fresh initialisation vector.

.. cpp:class:: StreamCipher

  .. cpp:function:: bool valid_iv_length(size_t iv_len) const

    This function returns true if and only if *length* is a valid
    IV length for the stream cipher.

  .. cpp:function:: void set_iv(const byte*, size_t len)

    Load IV into the stream cipher state. This should happen after the key is
    set and before any operation (encrypt/decrypt/seek) is called.

  .. cpp:function:: void seek(u64bit offset)

    Sets the state of the stream cipher and keystream according to the passed *offset*.
    Therefore the key and the IV (if required) have to be set beforehand.

  .. cpp:function:: void cipher(const byte* in, byte* out, size_t n)

    Processes *n* bytes plain/ciphertext from *in* and writes the result to *out*.

  .. cpp:function:: void cipher1(byte* inout, size_t n)

    Processes *n* bytes plain/ciphertext in place. Acts like :cpp:func:`cipher`\ (inout, inout, n).

  .. cpp:function:: void encipher(std::vector<byte> inout)
  .. cpp:function:: void encrypt(std::vector<byte> inout)
  .. cpp:function:: void decrypt(std::vector<byte> inout)

    Processes plain/ciphertext *inout* in place. Acts like :cpp:func:`cipher`\ (inout.data(), inout.data(), inout.size()).

Botan provides the following stream ciphers:

#. ChaCha
#. Salsa20
#. SHAKE-128
#. RC4

Code Example
""""""""""""""
The following code encrypts a provided plaintext using ChaCha20.

.. code-block:: cpp

    #include <botan/stream_cipher.h>
    #include <botan/rng.h>
    #include <botan/auto_rng.h>
    #include <botan/hex.h>
    #include <iostream>


    int main()
       {
       std::string plaintext("This is a tasty burger!");
       std::vector<uint8_t> pt(plaintext.data(),plaintext.data()+plaintext.length());
       const std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
       std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("ChaCha"));

       //generate fresh nonce (IV)
       std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
       std::vector<uint8_t> iv(8);
       rng->randomize(iv.data(),iv.size());

       //set key and IV
       cipher->set_key(key);
       cipher->set_iv(iv.data(),iv.size());
       std::cout << std::endl << cipher->name() << " with iv " << Botan::hex_encode(iv) << std::endl;
       cipher->encipher(pt);
       std::cout << Botan::hex_encode(pt);

       return 0;
       }



Message Authentication Codes (MAC)
----------------------------------
A Message Authentication Code algorithm computes a tag over a message utilizing a shared secret key.
Thus a valid tag confirms the authenticity and integrity of the associated data.
Only entities in possesion of the shared secret key are able to verify the tag.
The base class ``MessageAuthenticationCode`` (in ``botan/mac.h``) implements the interfaces
:cpp:class:`SymmetricAlgorithm` and :cpp:class:`BufferedComputation` (see Hash).

.. note::
    Avoid MAC-then-encrypt if possible and use encrypt-then-MAC.

Currently the following MAC algorithms are available in Botan:

- CBC-MAC (with AES-128/DES)
- CMAC / OMAC (with AES-128/AES-192/AES-256/Blowfish/Threefish-512)
- GMAC (with AES-128/AES-192/AES-256)
- HMAC (with MD5, RIPEMD-160, SHA-1, SHA-256)
- Poly1305
- SipHash
- x9.19-MAC

The Botan MAC computation is split into five stages.

#. Instantiate the MAC algorithm.
#. Set the secret key.
#. Process IV.
#. Process data.
#. Finalize the MAC computation.

.. cpp:class:: MessageAuthenticationCode

  .. cpp:function:: void set_key(const byte* key, size_t length)

    Set the shared MAC key for the calculation. This function has to be called before the data is processed.

  .. cpp:function:: void start(const byte* nonce, size_t nonce_len)

    Set the IV for the MAC calculation. Note that not all MAC algorithms require an IV.
    If an IV is required, the function has to be called before the data is processed.

  .. cpp:function:: void update(const byte* input, size_t length)
  .. cpp:function:: void update(const secure_vector<byte>& in)

    Process the passed data.

  .. cpp:function:: void update(byte in)

    Process a single byte.

  .. cpp:function:: void final(byte* out)

    Complete the MAC computation and write the calculated tag to the passed byte array.

  .. cpp:function:: secure_vector<byte> final()

    Complete the MAC computation and return the calculated tag.

  .. cpp:function:: bool verify_mac(const byte* mac, size_t length)

    Finalize the current MAC computation and compare the result to the passed ``mac``. Returns ``true``, if the verification is successfull and false otherwise.


Code Example
""""""""""""""""""""""
The following example code computes a AES-256 GMAC and subsequently verifies the tag.

.. code-block:: cpp

    #include <botan/mac.h>
    #include <botan/hex.h>
    #include <iostream>

    int main()
       {
       const std::vector<uint8_t> key = Botan::hex_decode("1337133713371337133713371337133713371337133713371337133713371337");
       const std::vector<uint8_t> iv = Botan::hex_decode("FFFFFFFFFFFFFFFFFFFFFFFF");
       const std::vector<uint8_t> data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");
       std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create("GMAC(AES-256)"));
       if(!mac)
          return 1;
       mac->set_key(key);
       mac->start(iv);
       mac->update(data);
       Botan::secure_vector<uint8_t> tag = mac->final();
       std::cout << mac->name() << ": " << Botan::hex_encode(tag) << std::endl;

       //Verify created MAC
       mac->start(iv);
       mac->update(data);
       std::cout << "Verification: " << (mac->verify_mac(tag) ? "success" : "failure");
       return 0;
       }

The following example code computes a valid AES-128 CMAC tag and modifies the data to demonstrate a MAC verification failure.

.. code-block:: cpp

  #include <botan/mac.h>
  #include <botan/hex.h>
  #include <iostream>

    int main()
       {
       const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
       std::vector<uint8_t> data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");
       std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create("CMAC(AES-128)"));
       if(!mac)
          return 1;
       mac->set_key(key);
       mac->update(data);
       Botan::secure_vector<uint8_t> tag = mac->final();
       //Corrupting data
       data.back()++;
       //Verify with corrupted data
       mac->update(data);
       std::cout << "Verification with malformed data: " << (mac->verify_mac(tag) ? "success" : "failure");
       return 0;
       }
