/*
* ElGamal
* (C) 1999-2007,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/elgamal.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/keypair.h>
#include <botan/reducer.h>
#include <botan/blinding.h>
#include <botan/pow_mod.h>

namespace Botan {

/*
* ElGamal_PublicKey Constructor
*/
ElGamal_PublicKey::ElGamal_PublicKey(const DL_Group& group, const BigInt& y) :
   DL_Scheme_PublicKey(group, y)
   {
   }

/*
* ElGamal_PrivateKey Constructor
*/
ElGamal_PrivateKey::ElGamal_PrivateKey(RandomNumberGenerator& rng,
                                       const DL_Group& group,
                                       const BigInt& x)
   {
   m_x = x;
   m_group = group;

   if(m_x.is_zero())
      {
      m_x.randomize(rng, group.exponent_bits());
      }

   m_y = m_group.power_g_p(m_x);
   }

ElGamal_PrivateKey::ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id,
                                       const secure_vector<uint8_t>& key_bits) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
   {
   m_y = m_group.power_g_p(m_x);
   }

/*
* Check Private ElGamal Parameters
*/
bool ElGamal_PrivateKey::check_key(RandomNumberGenerator& rng,
                                   bool strong) const
   {
   if(!DL_Scheme_PrivateKey::check_key(rng, strong))
      return false;

   if(!strong)
      return true;

   return KeyPair::encryption_consistency_check(rng, *this, "EME1(SHA-256)");
   }

namespace {

/**
* ElGamal encryption operation
*/
class ElGamal_Encryption_Operation final : public PK_Ops::Encryption_with_EME
   {
   public:

      size_t max_raw_input_bits() const override { return m_group.p_bits() - 1; }

      ElGamal_Encryption_Operation(const ElGamal_PublicKey& key, const std::string& eme);

      secure_vector<uint8_t> raw_encrypt(const uint8_t msg[], size_t msg_len,
                                      RandomNumberGenerator& rng) override;

   private:
      const DL_Group m_group;
      Fixed_Base_Power_Mod m_powermod_y_p;
   };

ElGamal_Encryption_Operation::ElGamal_Encryption_Operation(const ElGamal_PublicKey& key,
                                                           const std::string& eme) :
   PK_Ops::Encryption_with_EME(eme),
   m_group(key.get_group()),
   m_powermod_y_p(key.get_y(), m_group.get_p())
   {
   }

secure_vector<uint8_t>
ElGamal_Encryption_Operation::raw_encrypt(const uint8_t msg[], size_t msg_len,
                                          RandomNumberGenerator& rng)
   {
   BigInt m(msg, msg_len);

   if(m >= m_group.get_p())
      throw Invalid_Argument("ElGamal encryption: Input is too large");

   const size_t k_bits = m_group.exponent_bits();
   const BigInt k(rng, k_bits);

   const BigInt a = m_group.power_g_p(k);
   const BigInt b = m_group.multiply_mod_p(m, m_powermod_y_p(k));

   return BigInt::encode_fixed_length_int_pair(a, b, m_group.p_bytes());
   }

/**
* ElGamal decryption operation
*/
class ElGamal_Decryption_Operation final : public PK_Ops::Decryption_with_EME
   {
   public:

      ElGamal_Decryption_Operation(const ElGamal_PrivateKey& key,
                                   const std::string& eme,
                                   RandomNumberGenerator& rng);

      secure_vector<uint8_t> raw_decrypt(const uint8_t msg[], size_t msg_len) override;
   private:
      const DL_Group m_group;
      Fixed_Exponent_Power_Mod m_powermod_x_p;
      Blinder m_blinder;
   };

ElGamal_Decryption_Operation::ElGamal_Decryption_Operation(const ElGamal_PrivateKey& key,
                                                           const std::string& eme,
                                                           RandomNumberGenerator& rng) :
   PK_Ops::Decryption_with_EME(eme),
   m_group(key.get_group()),
   m_powermod_x_p(key.get_x(), m_group.get_p()),
   m_blinder(m_group.get_p(),
             rng,
             [](const BigInt& k) { return k; },
             [this](const BigInt& k) { return m_powermod_x_p(k); })
   {
   }

secure_vector<uint8_t>
ElGamal_Decryption_Operation::raw_decrypt(const uint8_t msg[], size_t msg_len)
   {
   const size_t p_bytes = m_group.p_bytes();

   if(msg_len != 2 * p_bytes)
      throw Invalid_Argument("ElGamal decryption: Invalid message");

   BigInt a(msg, p_bytes);
   const BigInt b(msg + p_bytes, p_bytes);

   if(a >= m_group.get_p() || b >= m_group.get_p())
      throw Invalid_Argument("ElGamal decryption: Invalid message");

   a = m_blinder.blind(a);

   const BigInt r = m_group.multiply_mod_p(m_group.inverse_mod_p(m_powermod_x_p(a)), b);

   return BigInt::encode_1363(m_blinder.unblind(r), p_bytes);
   }

}

std::unique_ptr<PK_Ops::Encryption>
ElGamal_PublicKey::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                        const std::string& params,
                                        const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Encryption>(new ElGamal_Encryption_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Decryption>
ElGamal_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
                                         const std::string& params,
                                         const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Decryption>(new ElGamal_Decryption_Operation(*this, params, rng));
   throw Provider_Not_Found(algo_name(), provider);
   }

}
