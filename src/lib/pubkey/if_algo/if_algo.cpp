/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/if_algo.h>
#include <botan/numthry.h>
#include <botan/workfactor.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

size_t IF_Scheme_PublicKey::estimated_strength() const
   {
   return if_work_factor(m_n.bits());
   }

AlgorithmIdentifier IF_Scheme_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(),
                              AlgorithmIdentifier::USE_NULL_PARAM);
   }

std::vector<byte> IF_Scheme_PublicKey::x509_subject_public_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(m_n)
         .encode(m_e)
      .end_cons()
      .get_contents_unlocked();
   }

IF_Scheme_PublicKey::IF_Scheme_PublicKey(const AlgorithmIdentifier&,
                                         const secure_vector<byte>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
        .decode(m_n)
        .decode(m_e)
      .verify_end()
      .end_cons();
   }

/*
* Check IF Scheme Public Parameters
*/
bool IF_Scheme_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   if(m_n < 35 || m_n.is_even() || m_e < 2)
      return false;
   return true;
   }

secure_vector<byte> IF_Scheme_PrivateKey::pkcs8_private_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(0))
         .encode(m_n)
         .encode(m_e)
         .encode(m_d)
         .encode(m_p)
         .encode(m_q)
         .encode(m_d1)
         .encode(m_d2)
         .encode(m_c)
      .end_cons()
   .get_contents();
   }

IF_Scheme_PrivateKey::IF_Scheme_PrivateKey(RandomNumberGenerator& rng,
                                           const AlgorithmIdentifier&,
                                           const secure_vector<byte>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
         .decode_and_check<size_t>(0, "Unknown PKCS #1 key format version")
         .decode(m_n)
         .decode(m_e)
         .decode(m_d)
         .decode(m_p)
         .decode(m_q)
         .decode(m_d1)
         .decode(m_d2)
         .decode(m_c)
      .end_cons();

   load_check(rng);
   }

IF_Scheme_PrivateKey::IF_Scheme_PrivateKey(RandomNumberGenerator& rng,
                                           const BigInt& prime1,
                                           const BigInt& prime2,
                                           const BigInt& exp,
                                           const BigInt& d_exp,
                                           const BigInt& mod) : 
      m_d{ d_exp }, m_p{ prime1 }, m_q{ prime2 }, m_d1{}, m_d2{}, m_c{ inverse_mod( m_q, m_p ) }
   {
   m_n = mod.is_nonzero() ? mod : m_p * m_q;
   m_e = exp;

   if(m_d == 0)
      {
      BigInt inv_for_d = lcm(m_p - 1, m_q - 1);
      if(m_e.is_even())
         inv_for_d >>= 1;

      m_d = inverse_mod(m_e, inv_for_d);
      }

   m_d1 = m_d % (m_p - 1);
   m_d2 = m_d % (m_q - 1);

   load_check(rng);
   }

/*
* Check IF Scheme Private Parameters
*/
bool IF_Scheme_PrivateKey::check_key(RandomNumberGenerator& rng,
                                     bool strong) const
   {
   if(m_n < 35 || m_n.is_even() || m_e < 2 || m_d < 2 || m_p < 3 || m_q < 3 || m_p*m_q != m_n)
      return false;

   if(m_d1 != m_d % (m_p - 1) || m_d2 != m_d % (m_q - 1) || m_c != inverse_mod(m_q, m_p))
      return false;

   const size_t prob = (strong) ? 56 : 12;

   if(!is_prime(m_p, rng, prob) || !is_prime(m_q, rng, prob))
      return false;
   return true;
   }

}
