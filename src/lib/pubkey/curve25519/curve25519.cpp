/*
* Curve25519
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/curve25519.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>

namespace Botan {

namespace {

void size_check(size_t size, const char* thing)
   {
   if(size != 32)
      throw Decoding_Error("Invalid size " + std::to_string(size) + " for Curve25519 " + thing);
   }

secure_vector<byte> curve25519(const secure_vector<byte>& secret,
                               const byte pubval[32])
   {
   secure_vector<byte> out(32);
   const int rc = curve25519_donna(out.data(), secret.data(), &pubval[0]);
   BOTAN_ASSERT_EQUAL(rc, 0, "Return value of curve25519_donna is ok");
   return out;
   }

secure_vector<byte> curve25519_basepoint(const secure_vector<byte>& secret)
   {
   const byte basepoint[32] = { 9 };
   return curve25519(secret, basepoint);
   }

}

AlgorithmIdentifier Curve25519_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(), AlgorithmIdentifier::USE_NULL_PARAM);
   }

bool Curve25519_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   return true; // no tests possible?
   }

Curve25519_PublicKey::Curve25519_PublicKey(const AlgorithmIdentifier&,
                                           const secure_vector<byte>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
      .decode(m_public, OCTET_STRING)
      .verify_end()
   .end_cons();

   size_check(m_public.size(), "public key");
   }

std::vector<byte> Curve25519_PublicKey::x509_subject_public_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
        .encode(m_public, OCTET_STRING)
      .end_cons()
      .get_contents_unlocked();
   }

Curve25519_PrivateKey::Curve25519_PrivateKey(RandomNumberGenerator& rng)
   {
   m_private = rng.random_vec(32);
   m_public = curve25519_basepoint(m_private);
   }

Curve25519_PrivateKey::Curve25519_PrivateKey(const AlgorithmIdentifier&,
                                             const secure_vector<byte>& key_bits,
                                             RandomNumberGenerator& rng)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
      .decode(m_public, OCTET_STRING)
      .decode(m_private, OCTET_STRING)
      .verify_end()
   .end_cons();

   size_check(m_public.size(), "public key");
   size_check(m_private.size(), "private key");

   load_check(rng);
   }

secure_vector<byte> Curve25519_PrivateKey::pkcs8_private_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
        .encode(m_public, OCTET_STRING)
        .encode(m_private, OCTET_STRING)
      .end_cons()
      .get_contents();
   }

bool Curve25519_PrivateKey::check_key(RandomNumberGenerator&, bool) const
   {
   return curve25519_basepoint(m_private) == m_public;
   }

secure_vector<byte> Curve25519_PrivateKey::agree(const byte w[], size_t w_len) const
   {
   size_check(w_len, "public value");

   return curve25519(m_private, w);
   }

}
