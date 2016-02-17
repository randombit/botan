McEliece
========================================

McEliece is a cryptographic scheme based on error correcting codes which is
thought to be resistent to quantum computers. First proposed in 1978, it is fast
and patent-free. Variants have been proposed and broken, but with suitable
parameters the original scheme remains secure. However the public keys are quite
large, which has hindered deployment in the past.

The implementation of McEliece in Botan was contributed by cryptosource GmbH. It
is based on the implementation HyMES, with the kind permission of Nicolas
Sendrier and INRIA to release a C++ adaption of their original C code under the
Botan license. It was then modified by Falko Strenzke to add side channel and
fault attack countermeasures. You can read more about the implementation at
http://www.cryptosource.de/docs/mceliece_in_botan.pdf

Encryption in the McEliece scheme consists of choosing a message block of size
`n`, encoding it in the error correcting code which is the public key, then
adding `t` bit errors. The code is created such that knowing only the public
key, decoding `t` errors is intractible, but with the additional knowledge of
the secret structure of the code a fast decoding technique exists.

The McEliece implementation in HyMES, and also in Botan, uses an optimization to
reduce the public key size, by converting the public key into a systemic code.
This means a portion of the public key is a identity matrix, and can be excluded
from the published public key. However it also means that in McEliece the
plaintext is represented directly in the ciphertext, with only a small number of
bit errors. Thus it is absolutely essential to only use McEliece with a CCA2
secure scheme.

One such scheme, KEM, is provided in Botan currently. It it a somewhat unusual
scheme in that it outputs two values, a symmetric key for use with an AEAD, and
an encrypted key. It does this by choosing a random plaintext (n - log2(n)*t
bits) using ``McEliece_PublicKey::random_plaintext_element``. Then a random
error mask is chosen and the message is coded and masked. The symmetric key is
SHA-512(plaintext || error_mask). As long as the resulting key is used with a
secure AEAD scheme (which can be used for transporting arbitrary amounts of
data), CCA2 security is provided.

In ``mcies.h`` there are functions for this combination:

.. cpp:function:: secure_vector<byte> mceies_encrypt(const McEliece_PublicKey& pubkey, \
                  const secure_vector<byte>& pt, \
                  byte ad[], size_t ad_len, \
                  RandomNumberGenerator& rng, \
                  const std::string& aead = "AES-256/OCB")

.. cpp:function:: secure_vector<byte> mceies_decrypt(const McEliece_PrivateKey& privkey, \
                                                     const secure_vector<byte>& ct, \
                                                     byte ad[], size_t ad_len, \
                                                     const std::string& aead = "AES-256/OCB")

For a given security level (SL) a McEliece key would use
parameters n and t, and have the cooresponding key sizes listed:

+-----+------+-----+---------------+----------------+
| SL  |   n  |   t | public key KB | private key KB |
+=====+======+=====+===============+================+
|  80 | 1632 |  33 |            59 |            140 |
+-----+------+-----+---------------+----------------+
| 107 | 2280 |  45 |           128 |            300 |
+-----+------+-----+---------------+----------------+
| 128 | 2960 |  57 |           195 |            459 |
+-----+------+-----+---------------+----------------+
| 147 | 3408 |  67 |           265 |            622 |
+-----+------+-----+---------------+----------------+
| 191 | 4624 |  95 |           516 |           1234 |
+-----+------+-----+---------------+----------------+
| 256 | 6624 | 115 |           942 |           2184 |
+-----+------+-----+---------------+----------------+

You can check the speed of McEliece with the suggested parameters above
using ``botan speed McEliece``, and can encrypt files using the ``botan mce``
command.
