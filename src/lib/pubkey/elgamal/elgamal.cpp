/*
* ElGamal
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/elgamal.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/keypair.h>
#include <botan/reducer.h>
#include <botan/blinding.h>
#include <botan/workfactor.h>
#include <botan/pow_mod.h>

namespace Botan {

/*
* ElGamal_PublicKey Constructor
*/
ElGamal_PublicKey::ElGamal_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   m_group = grp;
   m_y = y1;
   }

/*
* ElGamal_PrivateKey Constructor
*/
ElGamal_PrivateKey::ElGamal_PrivateKey(RandomNumberGenerator& rng,
                                       const DL_Group& grp,
                                       const BigInt& x_arg)
   {
   m_group = grp;
   m_x = x_arg;

   if(m_x == 0)
      m_x.randomize(rng, dl_exponent_size(group_p().bits()));

   m_y = power_mod(group_g(), m_x, group_p());
   }

ElGamal_PrivateKey::ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id,
                                       const secure_vector<uint8_t>& key_bits) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
   {
   m_y = power_mod(group_g(), m_x, group_p());
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

      size_t max_raw_input_bits() const override { return m_mod_p.get_modulus().bits() - 1; }

      ElGamal_Encryption_Operation(const ElGamal_PublicKey& key, const std::string& eme);

      secure_vector<uint8_t> raw_encrypt(const uint8_t msg[], size_t msg_len,
                                      RandomNumberGenerator& rng) override;

   private:
      Fixed_Base_Power_Mod m_powermod_g_p, m_powermod_y_p;
      Modular_Reducer m_mod_p;
   };

ElGamal_Encryption_Operation::ElGamal_Encryption_Operation(const ElGamal_PublicKey& key,
                                                           const std::string& eme) :
   PK_Ops::Encryption_with_EME(eme)
   {
   const BigInt& p = key.group_p();

   m_powermod_g_p = Fixed_Base_Power_Mod(key.group_g(), p);
   m_powermod_y_p = Fixed_Base_Power_Mod(key.get_y(), p);
   m_mod_p = Modular_Reducer(p);
   }

secure_vector<uint8_t>
ElGamal_Encryption_Operation::raw_encrypt(const uint8_t msg[], size_t msg_len,
                                          RandomNumberGenerator& rng)
   {
   const BigInt& p = m_mod_p.get_modulus();

   BigInt m(msg, msg_len);

   if(m >= p)
      throw Invalid_Argument("ElGamal encryption: Input is too large");

   BigInt k(rng, dl_exponent_size(p.bits()));

   BigInt a = m_powermod_g_p(k);
   BigInt b = m_mod_p.multiply(m, m_powermod_y_p(k));

   secure_vector<uint8_t> output(2*p.bytes());
   a.binary_encode(&output[p.bytes() - a.bytes()]);
   b.binary_encode(&output[output.size() / 2 + (p.bytes() - b.bytes())]);
   return output;
   }

/**
* ElGamal decryption operation
*/
class ElGamal_Decryption_Operation final : public PK_Ops::Decryption_with_EME
   {
   public:

      size_t max_raw_input_bits() const override
         { return m_mod_p.get_modulus().bits() - 1; }

      ElGamal_Decryption_Operation(const ElGamal_PrivateKey& key,
                                   const std::string& eme,
                                   RandomNumberGenerator& rng);

      secure_vector<uint8_t> raw_decrypt(const uint8_t msg[], size_t msg_len) override;
   private:
      Fixed_Exponent_Power_Mod m_powermod_x_p;
      Modular_Reducer m_mod_p;
      Blinder m_blinder;
   };

ElGamal_Decryption_Operation::ElGamal_Decryption_Operation(const ElGamal_PrivateKey& key,
                                                           const std::string& eme,
                                                           RandomNumberGenerator& rng) :
   PK_Ops::Decryption_with_EME(eme),
   m_powermod_x_p(Fixed_Exponent_Power_Mod(key.get_x(), key.group_p())),
   m_mod_p(Modular_Reducer(key.group_p())),
   m_blinder(key.group_p(),
             rng,
             [](const BigInt& k) { return k; },
             [this](const BigInt& k) { return m_powermod_x_p(k); })
   {
   }

secure_vector<uint8_t>
ElGamal_Decryption_Operation::raw_decrypt(const uint8_t msg[], size_t msg_len)
   {
   const BigInt& p = m_mod_p.get_modulus();

   const size_t p_bytes = p.bytes();

   if(msg_len != 2 * p_bytes)
      throw Invalid_Argument("ElGamal decryption: Invalid message");

   BigInt a(msg, p_bytes);
   BigInt b(msg + p_bytes, p_bytes);

   if(a >= p || b >= p)
      throw Invalid_Argument("ElGamal decryption: Invalid message");

   a = m_blinder.blind(a);

   BigInt r = m_mod_p.multiply(b, inverse_mod(m_powermod_x_p(a), p));

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
