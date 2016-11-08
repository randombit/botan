/*
* DSA
* (C) 1999-2010,2014,2016 Jack Lloyd
* (C) 2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dsa.h>
#include <botan/keypair.h>
#include <botan/pow_mod.h>
#include <botan/reducer.h>
#include <botan/internal/pk_ops_impl.h>

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
  #include <botan/emsa.h>
  #include <botan/rfc6979.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
  #include <future>
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
      m_x = BigInt::random_integer(rng, 2, group_q() - 1);
   else
      m_x = x_arg;

   m_y = power_mod(group_g(), m_x, group_p());
   }

DSA_PrivateKey::DSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                               const secure_vector<byte>& key_bits) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
   {
   m_y = power_mod(group_g(), m_x, group_p());
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
class DSA_Signature_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      DSA_Signature_Operation(const DSA_PrivateKey& dsa, const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_q(dsa.group_q()),
         m_x(dsa.get_x()),
         m_powermod_g_p(dsa.group_g(), dsa.group_p()),
         m_mod_q(dsa.group_q()),
         m_emsa(emsa)
         {
         }

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return m_q.bytes(); }
      size_t max_input_bits() const override { return m_q.bits(); }

      secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                   RandomNumberGenerator& rng) override;
   private:
      const BigInt& m_q;
      const BigInt& m_x;
      Fixed_Base_Power_Mod m_powermod_g_p;
      Modular_Reducer m_mod_q;
      std::string m_emsa;
   };

secure_vector<byte>
DSA_Signature_Operation::raw_sign(const byte msg[], size_t msg_len,
                                  RandomNumberGenerator& rng)
   {
   BigInt i(msg, msg_len);

   while(i >= m_q)
      i -= m_q;

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   BOTAN_UNUSED(rng);
   const BigInt k = generate_rfc6979_nonce(m_x, m_q, i, hash_for_emsa(m_emsa));
#else
   const BigInt k = BigInt::random_integer(rng, 1, m_q);
#endif

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   auto future_r = std::async(std::launch::async,
                              [&]() { return m_mod_q.reduce(m_powermod_g_p(k)); });

   BigInt s = inverse_mod(k, m_q);
   const BigInt r = future_r.get();
#else
   BigInt s = inverse_mod(k, m_q);
   const BigInt r = m_mod_q.reduce(m_powermod_g_p(k));
#endif

   s = m_mod_q.multiply(s, mul_add(m_x, r, i));

   // With overwhelming probability, a bug rather than actual zero r/s
   BOTAN_ASSERT(s != 0, "invalid s");
   BOTAN_ASSERT(r != 0, "invalid r");

   return BigInt::encode_fixed_length_int_pair(r, s, m_q.bytes());
   }

/**
* Object that can verify a DSA signature
*/
class DSA_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:
      DSA_Verification_Operation(const DSA_PublicKey& dsa,
                                 const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_q(dsa.group_q()), m_y(dsa.get_y()), m_powermod_g_p{Fixed_Base_Power_Mod(dsa.group_g(), dsa.group_p())},
         m_powermod_y_p{Fixed_Base_Power_Mod(m_y, dsa.group_p())}, m_mod_p{Modular_Reducer(dsa.group_p())},
         m_mod_q{Modular_Reducer(dsa.group_q())}
         {}

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return m_q.bytes(); }
      size_t max_input_bits() const override { return m_q.bits(); }

      bool with_recovery() const override { return false; }

      bool verify(const byte msg[], size_t msg_len,
                  const byte sig[], size_t sig_len) override;
   private:
      const BigInt& m_q;
      const BigInt& m_y;

      Fixed_Base_Power_Mod m_powermod_g_p, m_powermod_y_p;
      Modular_Reducer m_mod_p, m_mod_q;
   };

bool DSA_Verification_Operation::verify(const byte msg[], size_t msg_len,
                                        const byte sig[], size_t sig_len)
   {
   if(sig_len != 2*m_q.bytes() || msg_len > m_q.bytes())
      return false;

   BigInt r(sig, m_q.bytes());
   BigInt s(sig + m_q.bytes(), m_q.bytes());
   BigInt i(msg, msg_len);

   if(r <= 0 || r >= m_q || s <= 0 || s >= m_q)
      return false;

   s = inverse_mod(s, m_q);

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   auto future_s_i = std::async(std::launch::async,
      [&]() { return m_powermod_g_p(m_mod_q.multiply(s, i)); });

   BigInt s_r = m_powermod_y_p(m_mod_q.multiply(s, r));
   BigInt s_i = future_s_i.get();
#else
   BigInt s_r = m_powermod_y_p(m_mod_q.multiply(s, r));
   BigInt s_i = m_powermod_g_p(m_mod_q.multiply(s, i));
#endif

   s = m_mod_p.multiply(s_i, s_r);

   return (m_mod_q.reduce(s) == r);
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
DSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                    const std::string& params,
                                    const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(new DSA_Signature_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

}
