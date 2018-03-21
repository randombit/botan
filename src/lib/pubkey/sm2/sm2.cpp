/*
* SM2 Signatures
* (C) 2017 Ribose Inc
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm2.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/hash.h>

namespace Botan {

bool SM2_Signature_PrivateKey::check_key(RandomNumberGenerator& rng,
                                         bool strong) const
   {
   if(!public_point().on_the_curve())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "SM3");
   }

SM2_Signature_PrivateKey::SM2_Signature_PrivateKey(const AlgorithmIdentifier& alg_id,
                                                   const secure_vector<uint8_t>& key_bits) :
   EC_PrivateKey(alg_id, key_bits)
   {
   m_da_inv = inverse_mod(m_private_key + 1, domain().get_order());
   }

SM2_Signature_PrivateKey::SM2_Signature_PrivateKey(RandomNumberGenerator& rng,
                                                   const EC_Group& domain,
                                                   const BigInt& x) :
   EC_PrivateKey(rng, domain, x)
   {
   m_da_inv = inverse_mod(m_private_key + 1, domain.get_order());
   }

std::vector<uint8_t> sm2_compute_za(HashFunction& hash,
                                    const std::string& user_id,
                                    const EC_Group& domain,
                                    const PointGFp& pubkey)
   {
   if(user_id.size() >= 8192)
      throw Invalid_Argument("SM2 user id too long to represent");

   const uint16_t uid_len = static_cast<uint16_t>(8 * user_id.size());

   hash.update(get_byte(0, uid_len));
   hash.update(get_byte(1, uid_len));
   hash.update(user_id);

   const size_t p_bytes = domain.get_p_bytes();

   hash.update(BigInt::encode_1363(domain.get_a(), p_bytes));
   hash.update(BigInt::encode_1363(domain.get_b(), p_bytes));
   hash.update(BigInt::encode_1363(domain.get_g_x(), p_bytes));
   hash.update(BigInt::encode_1363(domain.get_g_y(), p_bytes));
   hash.update(BigInt::encode_1363(pubkey.get_affine_x(), p_bytes));
   hash.update(BigInt::encode_1363(pubkey.get_affine_y(), p_bytes));

   std::vector<uint8_t> za(hash.output_length());
   hash.final(za.data());

   return za;
   }

namespace {

/**
* SM2 signature operation
*/
class SM2_Signature_Operation final : public PK_Ops::Signature
   {
   public:

      SM2_Signature_Operation(const SM2_Signature_PrivateKey& sm2,
                              const std::string& ident,
                              const std::string& hash) :
         m_group(sm2.domain()),
         m_x(sm2.private_value()),
         m_da_inv(sm2.get_da_inv()),
         m_hash(HashFunction::create_or_throw(hash))
         {
         // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
         m_za = sm2_compute_za(*m_hash, ident, m_group, sm2.public_point());
         m_hash->update(m_za);
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_hash->update(msg, msg_len);
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override;

   private:
      const EC_Group m_group;
      const BigInt& m_x;
      const BigInt& m_da_inv;

      std::vector<uint8_t> m_za;
      std::unique_ptr<HashFunction> m_hash;
      std::vector<BigInt> m_ws;
   };

secure_vector<uint8_t>
SM2_Signature_Operation::sign(RandomNumberGenerator& rng)
   {
   const BigInt e = BigInt::decode(m_hash->final());

   const BigInt k = m_group.random_scalar(rng);

   const BigInt r = m_group.mod_order(
      m_group.blinded_base_point_multiply_x(k, rng, m_ws) + e);
   const BigInt s = m_group.multiply_mod_order(m_da_inv, (k - r*m_x));

   // prepend ZA for next signature if any
   m_hash->update(m_za);

   return BigInt::encode_fixed_length_int_pair(r, s, m_group.get_order().bytes());
   }

/**
* SM2 verification operation
*/
class SM2_Verification_Operation final : public PK_Ops::Verification
   {
   public:
      SM2_Verification_Operation(const SM2_Signature_PublicKey& sm2,
                                 const std::string& ident,
                                 const std::string& hash) :
         m_group(sm2.domain()),
         m_public_point(sm2.public_point()),
         m_hash(HashFunction::create_or_throw(hash))
         {
         // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
         m_za = sm2_compute_za(*m_hash, ident, m_group, m_public_point);
         m_hash->update(m_za);
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_hash->update(msg, msg_len);
         }

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override;
   private:
      const EC_Group m_group;
      const PointGFp& m_public_point;
      std::vector<uint8_t> m_za;
      std::unique_ptr<HashFunction> m_hash;
   };

bool SM2_Verification_Operation::is_valid_signature(const uint8_t sig[], size_t sig_len)
   {
   const BigInt e = BigInt::decode(m_hash->final());

   // Update for next verification
   m_hash->update(m_za);

   if(sig_len != m_group.get_order().bytes()*2)
      return false;

   const BigInt r(sig, sig_len / 2);
   const BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order())
      return false;

   const BigInt t = m_group.mod_order(r + s);

   if(t == 0)
      return false;

   const PointGFp R = m_group.point_multiply(s, m_public_point, t);

   // ???
   if(R.is_zero())
      return false;

   return (m_group.mod_order(R.get_affine_x() + e) == r);
   }

}

std::unique_ptr<PK_Ops::Verification>
SM2_Signature_PublicKey::create_verification_op(const std::string& params,
                                                const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      std::string userid = "";
      std::string hash = "SM3";

      auto comma = params.find(',');
      if(comma == std::string::npos)
         userid = params;
      else
         {
         userid = params.substr(0, comma);
         hash = params.substr(comma+1, std::string::npos);
         }

      if (userid.empty())
         {
         // GM/T 0009-2012 specifies this as the default userid
         userid = "1234567812345678";
         }

      return std::unique_ptr<PK_Ops::Verification>(new SM2_Verification_Operation(*this, userid, hash));
      }

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
SM2_Signature_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                              const std::string& params,
                                              const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      std::string userid = "";
      std::string hash = "SM3";

      auto comma = params.find(',');
      if(comma == std::string::npos)
         userid = params;
      else
         {
         userid = params.substr(0, comma);
         hash = params.substr(comma+1, std::string::npos);
         }

      if (userid.empty())
         {
         // GM/T 0009-2012 specifies this as the default userid
         userid = "1234567812345678";
         }

      return std::unique_ptr<PK_Ops::Signature>(new SM2_Signature_Operation(*this, userid, hash));
      }

   throw Provider_Not_Found(algo_name(), provider);
   }

}
