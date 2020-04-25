
.. _mac:

Message Authentication Codes (MAC)
===================================

A Message Authentication Code algorithm computes a tag over a message utilizing
a shared secret key. Thus a valid tag confirms the authenticity and integrity of
the message. Only entities in possession of the shared secret key are able to
verify the tag.

.. note::

    When combining a MAC with unauthenticated encryption mode, prefer to first
    encrypt the message and then MAC the ciphertext. The alternative is to MAC
    the plaintext, which depending on exact usage can suffer serious security
    issues. For a detailed discussion of this issue see the paper "The Order of
    Encryption and Authentication for Protecting Communications" by Hugo
    Krawczyk

The Botan MAC computation is split into five stages.

#. Instantiate the MAC algorithm.
#. Set the secret key.
#. Process IV.
#. Process data.
#. Finalize the MAC computation.

.. cpp:class:: MessageAuthenticationCode

  .. cpp:function:: std::string name() const

     Returns a human-readable string of the name of this algorithm.

  .. cpp:function:: void clear()

     Clear the key.

  .. cpp:function:: MessageAuthenticationCode* clone() const

     Return a newly allocated object of the same type as this one.

  .. cpp:function:: void set_key(const uint8_t* key, size_t length)

    Set the shared MAC key for the calculation. This function has to be called before the data is processed.

  .. cpp:function:: bool valid_keylength(size_t length) const

     This function returns true if and only if *length* is a valid
     keylength for the algorithm.

  .. cpp:function:: size_t minimum_keylength() const

     Return the smallest key length (in bytes) that is acceptable for the
     algorithm.

  .. cpp:function:: size_t maximum_keylength() const

     Return the largest key length (in bytes) that is acceptable for the
     algorithm.

  .. cpp:function:: void start(const uint8_t* nonce, size_t nonce_len)

    Set the IV for the MAC calculation. Note that not all MAC algorithms require an IV.
    If an IV is required, the function has to be called before the data is processed.
    For algorithms that don't require it, the call can be omitted, or else called
    with ``nonce_len`` of zero.

  .. cpp:function:: void update(const uint8_t* input, size_t length)

     Process the passed data.

  .. cpp:function:: void update(const secure_vector<uint8_t>& in)

    Process the passed data.

  .. cpp:function:: void update(uint8_t in)

    Process a single byte.

  .. cpp:function:: void final(uint8_t* out)

    Complete the MAC computation and write the calculated tag to the passed byte array.

  .. cpp:function:: secure_vector<uint8_t> final()

    Complete the MAC computation and return the calculated tag.

  .. cpp:function:: bool verify_mac(const uint8_t* mac, size_t length)

    Finalize the current MAC computation and compare the result to the passed
    ``mac``. Returns ``true``, if the verification is successful and false
    otherwise.


Code Examples
------------------------

The following example computes an HMAC with a random key then verifies the tag.

    #include <botan/mac.h>
    #include <botan/hex.h>
    #include <botan/system_rng.h>
    #include <assert.h>

    std::string compute_mac(const std::string& msg, const Botan::secure_vector<uint8_t>& key)
       {
       auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

       hmac->set_key(key);
       hmac->update(msg);

       return Botan::hex_encode(hmac->final());
       }

    int main()
       {
       Botan::System_RNG rng;

       const auto key = rng.random_vec(32); // 256 bit random key

       // "Message" != "Mussage" so tags will also not match
       std::string tag1 = compute_mac("Message", key);
       std::string tag2 = compute_mac("Mussage", key);
       assert(tag1 != tag2);

       // Recomputing with original input message results in identical tag
       std::string tag3 = compute_mac("Message", key);
       assert(tag1 == tag3);
       }


The following example code computes a AES-256 GMAC and subsequently verifies the
tag.  Unlike most other MACs, GMAC requires a nonce *which must not repeat or
all security is lost*.

.. code-block:: cpp

    #include <botan/mac.h>
    #include <botan/hex.h>
    #include <iostream>

    int main()
       {
       const std::vector<uint8_t> key = Botan::hex_decode("1337133713371337133713371337133713371337133713371337133713371337");
       const std::vector<uint8_t> nonce = Botan::hex_decode("FFFFFFFFFFFFFFFFFFFFFFFF");
       const std::vector<uint8_t> data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");
       std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create("GMAC(AES-256)"));
       if(!mac)
          return 1;
       mac->set_key(key);
       mac->start(nonce);
       mac->update(data);
       Botan::secure_vector<uint8_t> tag = mac->final();
       std::cout << mac->name() << ": " << Botan::hex_encode(tag) << std::endl;

       //Verify created MAC
       mac->start(nonce);
       mac->update(data);
       std::cout << "Verification: " << (mac->verify_mac(tag) ? "success" : "failure");
       return 0;
       }

The following example code computes a valid AES-128 CMAC tag and modifies the
data to demonstrate a MAC verification failure.

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

Available MACs
------------------------------------------

Currently the following MAC algorithms are available in Botan. In new code,
default to HMAC with a strong hash like SHA-256 or SHA-384.

CBC-MAC
~~~~~~~~~~~~

An older authentication code based on a block cipher. Serious security problems,
in particular **insecure** if messages of several different lengths are
authenticated. Avoid unless required for compatibility.

Available if ``BOTAN_HAS_CBC_MAC`` is defined.

.. warning::
   CBC-MAC support is deprecated and will be removed in a future major release.

CMAC
~~~~~~~~~~~~

A modern CBC-MAC variant that avoids the security problems of plain CBC-MAC.
Approved by NIST. Also sometimes called OMAC.

Available if ``BOTAN_HAS_CMAC`` is defined.

GMAC
~~~~~~~~~~~~

GMAC is related to the GCM authenticated cipher mode. It is quite slow unless
hardware support for carryless multiplications is available. A new nonce
must be used with **each** message authenticated, or otherwise all security is
lost.

Available if ``BOTAN_HAS_GMAC`` is defined.

.. warning::
   Due to the nonce requirement, GMAC is exceptionally fragile. Avoid it unless
   absolutely required.

HMAC
~~~~~~~~~~~~

A message authentication code based on a hash function. Very commonly used.

Available if ``BOTAN_HAS_HMAC`` is defined.

Poly1305
~~~~~~~~~~~~

A polynomial mac (similar to GMAC). Very fast, but tricky to use safely. Forms
part of the ChaCha20Poly1305 AEAD mode. A new key must be used for **each**
message, or all security is lost.

Available if ``BOTAN_HAS_POLY1305`` is defined.

.. warning::
   Due to the nonce requirement, Poly1305 is exceptionally fragile. Avoid it unless
   absolutely required.

SipHash
~~~~~~~~~~~~

A modern and very fast PRF. Produces only a 64-bit output. Defaults to
"SipHash(2,4)" which is the recommended configuration, using 2 rounds for each
input block and 4 rounds for finalization.

Available if ``BOTAN_HAS_SIPHASH`` is defined.

X9.19-MAC
~~~~~~~~~~~~

A CBC-MAC variant sometimes used in finance. Always uses DES.
Sometimes called the "DES retail MAC", also standardized in ISO 9797-1.

It is slow and has known attacks. Avoid unless required.

Available if ``BOTAN_HAS_X919_MAC`` is defined.
