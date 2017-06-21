/*
* SM2
* (C) Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm2.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/keypair.h>
#include <botan/reducer.h>
#include <botan/hash.h>

#include <iostream>
#include <botan/hex.h>

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

namespace {

std::vector<uint8_t> compute_za(HashFunction& hash,
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

   const size_t p_bytes = domain.get_curve().get_p().bytes();

   hash.update(BigInt::encode_1363(domain.get_curve().get_a(), p_bytes));
   hash.update(BigInt::encode_1363(domain.get_curve().get_b(), p_bytes));
   hash.update(BigInt::encode_1363(domain.get_base_point().get_affine_x(), p_bytes));
   hash.update(BigInt::encode_1363(domain.get_base_point().get_affine_y(), p_bytes));
   hash.update(BigInt::encode_1363(pubkey.get_affine_x(), p_bytes));
   hash.update(BigInt::encode_1363(pubkey.get_affine_y(), p_bytes));

   std::vector<uint8_t> za(hash.output_length());
   hash.final(za.data());

   #if 0
   std::cout << "Ent0 " << (int)get_byte(0, uid_len) << "\n";
   std::cout << "Ent1 " << (int)get_byte(1, uid_len) << "\n";
   std::cout << "ID " << user_id << "\n";
   std::cout << "A = " << Botan::hex_encode(BigInt::encode_1363(domain.get_curve().get_a(), p_bytes)) << "\n";
   std::cout << "B = " << Botan::hex_encode(BigInt::encode_1363(domain.get_curve().get_b(), p_bytes)) << "\n";
   std::cout << "xG = " << Botan::hex_encode(BigInt::encode_1363(domain.get_base_point().get_affine_x(), p_bytes)) << "\n";
   std::cout << "yG = " << Botan::hex_encode(BigInt::encode_1363(domain.get_base_point().get_affine_y(), p_bytes)) << "\n";
   std::cout << "xP = " << Botan::hex_encode(BigInt::encode_1363(pubkey.get_affine_x(), p_bytes)) << "\n";
   std::cout << "yP = " << Botan::hex_encode(BigInt::encode_1363(pubkey.get_affine_y(), p_bytes)) << "\n";
   std::cout << "ZA = " << hex_encode(za) << "\n";
   #endif
   
   return za;
   }

/**
* SM2 signature operation
*/
class SM2_Signature_Operation : public PK_Ops::Signature
   {
   public:

      SM2_Signature_Operation(const SM2_Signature_PrivateKey& sm2,
                              const std::string& ident) :
         m_order(sm2.domain().get_order()),
         m_base_point(sm2.domain().get_base_point(), m_order),
         m_x(sm2.private_value()),
         m_da_inv(sm2.get_da_inv()),
         m_mod_order(m_order),
         m_hash(HashFunction::create_or_throw("SM3"))
         {
         // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
         m_za = compute_za(*m_hash, ident, sm2.domain(), sm2.public_point());
         m_hash->update(m_za);
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_hash->update(msg, msg_len);
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override;

   private:
      const BigInt& m_order;
      Blinded_Point_Multiply m_base_point;
      const BigInt& m_x;
      const BigInt& m_da_inv;
      Modular_Reducer m_mod_order;

      std::vector<uint8_t> m_za;
      std::unique_ptr<HashFunction> m_hash;
   };

secure_vector<uint8_t>
SM2_Signature_Operation::sign(RandomNumberGenerator& rng)
   {
   const BigInt k = BigInt::random_integer(rng, 1, m_order);

   const PointGFp k_times_P = m_base_point.blinded_multiply(k, rng);

   const BigInt e = BigInt::decode(m_hash->final());
   const BigInt r = m_mod_order.reduce(k_times_P.get_affine_x() + e);
   const BigInt s = m_mod_order.multiply(m_da_inv, (k - r*m_x));

   // prepend ZA for next signature if any
   m_hash->update(m_za);

   return BigInt::encode_fixed_length_int_pair(r, s, m_order.bytes());
   }

/**
* SM2 verification operation
*/
class SM2_Verification_Operation : public PK_Ops::Verification
   {
   public:
      SM2_Verification_Operation(const SM2_Signature_PublicKey& sm2,
                                 const std::string& ident) :
         m_base_point(sm2.domain().get_base_point()),
         m_public_point(sm2.public_point()),
         m_order(sm2.domain().get_order()),
         m_mod_order(m_order),
         m_hash(HashFunction::create_or_throw("SM3"))
         {
         // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
         m_za = compute_za(*m_hash, ident, sm2.domain(), sm2.public_point());
         m_hash->update(m_za);
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_hash->update(msg, msg_len);
         }

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override;
   private:
      const PointGFp& m_base_point;
      const PointGFp& m_public_point;
      const BigInt& m_order;
      // FIXME: should be offered by curve
      Modular_Reducer m_mod_order;
      std::vector<uint8_t> m_za;
      std::unique_ptr<HashFunction> m_hash;
   };

bool SM2_Verification_Operation::is_valid_signature(const uint8_t sig[], size_t sig_len)
   {
   const BigInt e = BigInt::decode(m_hash->final());

   // Update for next verification
   m_hash->update(m_za);

   if(sig_len != m_order.bytes()*2)
      return false;

   const BigInt r(sig, sig_len / 2);
   const BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= m_order || s <= 0 || s >= m_order)
      return false;

   const BigInt t = m_mod_order.reduce(r + s);

   if(t == 0)
      return false;

   const PointGFp R = multi_exponentiate(m_base_point, s, m_public_point, t);

   // ???
   if(R.is_zero())
      return false;

   return (m_mod_order.reduce(R.get_affine_x() + e) == r);
   }

}

std::unique_ptr<PK_Ops::Verification>
SM2_Signature_PublicKey::create_verification_op(const std::string& params,
                                                const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Verification>(new SM2_Verification_Operation(*this, params));

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
SM2_Signature_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                              const std::string& params,
                                              const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(new SM2_Signature_Operation(*this, params));

   throw Provider_Not_Found(algo_name(), provider);
   }

}
