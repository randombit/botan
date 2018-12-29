/*
* DSA
* (C) 1999-2010,2014,2016 Jack Lloyd
* (C) 2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dsa.h>
#include <botan/keypair.h>
#include <botan/reducer.h>
#include <botan/rng.h>
#include <botan/divide.h>
#include <botan/internal/pk_ops_impl.h>

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
  #include <botan/emsa.h>
  #include <botan/rfc6979.h>
#endif

namespace Botan {

/*
* DSA_PublicKey Constructor
*/
DSA_PublicKey::DSA_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   m_group = grp;
   m_y = y1;
   }

/*
* Create a DSA private key
*/
DSA_PrivateKey::DSA_PrivateKey(RandomNumberGenerator& rng,
                               const DL_Group& grp,
                               const BigInt& x_arg)
   {
   m_group = grp;

   if(x_arg == 0)
      m_x = BigInt::random_integer(rng, 2, group_q());
   else
      m_x = x_arg;

   m_y = m_group.power_g_p(m_x, m_group.q_bits());
   }

DSA_PrivateKey::DSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                               const secure_vector<uint8_t>& key_bits) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
   {
   m_y = m_group.power_g_p(m_x, m_group.q_bits());
   }

/*
* Check Private DSA Parameters
*/
bool DSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!DL_Scheme_PrivateKey::check_key(rng, strong) || m_x >= group_q())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
   }

namespace {

/**
* Object that can create a DSA signature
*/
class DSA_Signature_Operation final : public PK_Ops::Signature_with_EMSA
   {
   public:
      DSA_Signature_Operation(const DSA_PrivateKey& dsa,
                              const std::string& emsa,
                              RandomNumberGenerator& rng) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_group(dsa.get_group()),
         m_x(dsa.get_x())
         {
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
         m_rfc6979_hash = hash_for_emsa(emsa);
#endif

         m_b = BigInt::random_integer(rng, 2, dsa.group_q());
         m_b_inv = m_group.inverse_mod_q(m_b);
         }

      size_t signature_length() const override { return 2*m_group.q_bytes(); }
      size_t max_input_bits() const override { return m_group.q_bits(); }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                   RandomNumberGenerator& rng) override;
   private:
      const DL_Group m_group;
      const BigInt& m_x;
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
      std::string m_rfc6979_hash;
#endif

      BigInt m_b, m_b_inv;
   };

secure_vector<uint8_t>
DSA_Signature_Operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                  RandomNumberGenerator& rng)
   {
   const BigInt& q = m_group.get_q();

   BigInt m(msg, msg_len, m_group.q_bits());

   while(m >= q)
      m -= q;

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   BOTAN_UNUSED(rng);
   const BigInt k = generate_rfc6979_nonce(m_x, q, m, m_rfc6979_hash);
#else
   const BigInt k = BigInt::random_integer(rng, 1, q);
#endif

   const BigInt k_inv = m_group.inverse_mod_q(k);

   /*
   * It may not be strictly necessary for the reduction (g^k mod p) mod q to be
   * const time, since r is published as part of the signature, and deriving
   * anything useful about k from g^k mod p would seem to require computing a
   * discrete logarithm.
   *
   * However it only increases the cost of signatures by about 7-10%, and DSA is
   * only for legacy use anyway so we don't care about the performance so much.
   */
   const BigInt r = ct_modulo(m_group.power_g_p(k, m_group.q_bits()), m_group.get_q());

   /*
   * Blind the input message and compute x*r+m as (x*r*b + m*b)/b
   */
   m_b = m_group.square_mod_q(m_b);
   m_b_inv = m_group.square_mod_q(m_b_inv);

   m = m_group.multiply_mod_q(m_b, m);
   const BigInt xr = m_group.multiply_mod_q(m_b, m_x, r);

   const BigInt s = m_group.multiply_mod_q(m_b_inv, k_inv, m_group.mod_q(xr+m));

   // With overwhelming probability, a bug rather than actual zero r/s
   if(r.is_zero() || s.is_zero())
      throw Internal_Error("Computed zero r/s during DSA signature");

   return BigInt::encode_fixed_length_int_pair(r, s, q.bytes());
   }

/**
* Object that can verify a DSA signature
*/
class DSA_Verification_Operation final : public PK_Ops::Verification_with_EMSA
   {
   public:
      DSA_Verification_Operation(const DSA_PublicKey& dsa,
                                 const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_group(dsa.get_group()),
         m_y(dsa.get_y())
         {
         }

      size_t max_input_bits() const override { return m_group.q_bits(); }

      bool with_recovery() const override { return false; }

      bool verify(const uint8_t msg[], size_t msg_len,
                  const uint8_t sig[], size_t sig_len) override;
   private:
      const DL_Group m_group;
      const BigInt& m_y;
   };

bool DSA_Verification_Operation::verify(const uint8_t msg[], size_t msg_len,
                                        const uint8_t sig[], size_t sig_len)
   {
   const BigInt& q = m_group.get_q();
   const size_t q_bytes = q.bytes();

   if(sig_len != 2*q_bytes || msg_len > q_bytes)
      return false;

   BigInt r(sig, q_bytes);
   BigInt s(sig + q_bytes, q_bytes);
   BigInt i(msg, msg_len, q.bits());

   if(r <= 0 || r >= q || s <= 0 || s >= q)
      return false;

   s = inverse_mod(s, q);

   const BigInt sr = m_group.multiply_mod_q(s, r);
   const BigInt si = m_group.multiply_mod_q(s, i);

   s = m_group.multi_exponentiate(si, m_y, sr);

   // s is too big for Barrett, and verification doesn't need to be const-time
   return (s % m_group.get_q() == r);
   }

}

std::unique_ptr<PK_Ops::Verification>
DSA_PublicKey::create_verification_op(const std::string& params,
                                      const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Verification>(new DSA_Verification_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
DSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                    const std::string& params,
                                    const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(new DSA_Signature_Operation(*this, params, rng));
   throw Provider_Not_Found(algo_name(), provider);
   }

}
