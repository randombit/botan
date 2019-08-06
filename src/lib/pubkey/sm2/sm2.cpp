/*
* SM2 Signatures
* (C) 2017,2018 Ribose Inc
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm2.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>
#include <botan/loadstor.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/hash.h>
#include <botan/parsing.h>

namespace Botan {

std::string SM2_PublicKey::algo_name() const
   {
   return "SM2";
   }

bool SM2_PrivateKey::check_key(RandomNumberGenerator& rng,
                               bool strong) const
   {
   if(!public_point().on_the_curve())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "user@example.com,SM3");
   }

SM2_PrivateKey::SM2_PrivateKey(const AlgorithmIdentifier& alg_id,
                               const secure_vector<uint8_t>& key_bits) :
   EC_PrivateKey(alg_id, key_bits)
   {
   m_da_inv = domain().inverse_mod_order(m_private_key + 1);
   }

SM2_PrivateKey::SM2_PrivateKey(RandomNumberGenerator& rng,
                               const EC_Group& domain,
                               const BigInt& x) :
   EC_PrivateKey(rng, domain, x)
   {
   m_da_inv = domain.inverse_mod_order(m_private_key + 1);
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

      SM2_Signature_Operation(const SM2_PrivateKey& sm2,
                              const std::string& ident,
                              const std::string& hash) :
         m_group(sm2.domain()),
         m_x(sm2.private_value()),
         m_da_inv(sm2.get_da_inv())
         {
         if(hash == "Raw")
            {
            // m_hash is null, m_za is empty
            }
         else
            {
            m_hash = HashFunction::create_or_throw(hash);
            // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
            m_za = sm2_compute_za(*m_hash, ident, m_group, sm2.public_point());
            m_hash->update(m_za);
            }
         }

      size_t signature_length() const override { return 2*m_group.get_order_bytes(); }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         if(m_hash)
            {
            m_hash->update(msg, msg_len);
            }
         else
            {
            m_digest.insert(m_digest.end(), msg, msg + msg_len);
            }
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override;

   private:
      const EC_Group m_group;
      const BigInt& m_x;
      const BigInt& m_da_inv;

      std::vector<uint8_t> m_za;
      secure_vector<uint8_t> m_digest;
      std::unique_ptr<HashFunction> m_hash;
      std::vector<BigInt> m_ws;
   };

secure_vector<uint8_t>
SM2_Signature_Operation::sign(RandomNumberGenerator& rng)
   {
   BigInt e;
   if(m_hash)
      {
      e = BigInt::decode(m_hash->final());
      // prepend ZA for next signature if any
      m_hash->update(m_za);
      }
   else
      {
      e = BigInt::decode(m_digest);
      m_digest.clear();
      }

   const BigInt k = m_group.random_scalar(rng);

   const BigInt r = m_group.mod_order(
      m_group.blinded_base_point_multiply_x(k, rng, m_ws) + e);
   const BigInt s = m_group.multiply_mod_order(m_da_inv, m_group.mod_order(k - r*m_x));

   return BigInt::encode_fixed_length_int_pair(r, s, m_group.get_order().bytes());
   }

/**
* SM2 verification operation
*/
class SM2_Verification_Operation final : public PK_Ops::Verification
   {
   public:
      SM2_Verification_Operation(const SM2_PublicKey& sm2,
                                 const std::string& ident,
                                 const std::string& hash) :
         m_group(sm2.domain()),
         m_gy_mul(m_group.get_base_point(), sm2.public_point())
         {
         if(hash == "Raw")
            {
            // m_hash is null, m_za is empty
            }
         else
            {
            m_hash = HashFunction::create_or_throw(hash);
            // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
            m_za = sm2_compute_za(*m_hash, ident, m_group, sm2.public_point());
            m_hash->update(m_za);
            }
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         if(m_hash)
            {
            m_hash->update(msg, msg_len);
            }
         else
            {
            m_digest.insert(m_digest.end(), msg, msg + msg_len);
            }
         }

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override;
   private:
      const EC_Group m_group;
      const PointGFp_Multi_Point_Precompute m_gy_mul;
      secure_vector<uint8_t> m_digest;
      std::vector<uint8_t> m_za;
      std::unique_ptr<HashFunction> m_hash;
   };

bool SM2_Verification_Operation::is_valid_signature(const uint8_t sig[], size_t sig_len)
   {
   BigInt e;
   if(m_hash)
      {
      e = BigInt::decode(m_hash->final());
      // prepend ZA for next signature if any
      m_hash->update(m_za);
      }
   else
      {
      e = BigInt::decode(m_digest);
      m_digest.clear();
      }

   if(sig_len != m_group.get_order().bytes()*2)
      return false;

   const BigInt r(sig, sig_len / 2);
   const BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order())
      return false;

   const BigInt t = m_group.mod_order(r + s);

   if(t == 0)
      return false;

   const PointGFp R = m_gy_mul.multi_exp(s, t);

   // ???
   if(R.is_zero())
      return false;

   return (m_group.mod_order(R.get_affine_x() + e) == r);
   }

void parse_sm2_param_string(const std::string& params,
                            std::string& userid,
                            std::string& hash)
   {
   // GM/T 0009-2012 specifies this as the default userid
   const std::string default_userid = "1234567812345678";

   // defaults:
   userid = default_userid;
   hash = "SM3";

   /*
   * SM2 parameters have the following possible formats:
   * Ident [since 2.2.0]
   * Ident,Hash [since 2.3.0]
   */

   auto comma = params.find(',');
   if(comma == std::string::npos)
      {
      userid = params;
      }
   else
      {
      userid = params.substr(0, comma);
      hash = params.substr(comma+1, std::string::npos);
      }
   }

}

std::unique_ptr<PK_Ops::Verification>
SM2_PublicKey::create_verification_op(const std::string& params,
                                      const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      std::string userid, hash;
      parse_sm2_param_string(params, userid, hash);
      return std::unique_ptr<PK_Ops::Verification>(new SM2_Verification_Operation(*this, userid, hash));
      }

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
SM2_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                    const std::string& params,
                                    const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      std::string userid, hash;
      parse_sm2_param_string(params, userid, hash);
      return std::unique_ptr<PK_Ops::Signature>(new SM2_Signature_Operation(*this, userid, hash));
      }

   throw Provider_Not_Found(algo_name(), provider);
   }

}
