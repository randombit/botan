/*
* SM2 Encryption
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm2_enc.h>
#include <botan/pk_ops.h>
#include <botan/keypair.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/kdf.h>
#include <botan/hash.h>

namespace Botan {

bool SM2_Encryption_PrivateKey::check_key(RandomNumberGenerator& rng,
                                          bool strong) const
   {
   if(!public_point().on_the_curve())
      return false;

   if(!strong)
      return true;

   return KeyPair::encryption_consistency_check(rng, *this, "SM3");
   }

SM2_Encryption_PrivateKey::SM2_Encryption_PrivateKey(const AlgorithmIdentifier& alg_id,
                                                     const secure_vector<uint8_t>& key_bits) :
   EC_PrivateKey(alg_id, key_bits)
   {
   }

SM2_Encryption_PrivateKey::SM2_Encryption_PrivateKey(RandomNumberGenerator& rng,
                                                     const EC_Group& domain,
                                                     const BigInt& x) :
   EC_PrivateKey(rng, domain, x)
   {
   }

namespace {

class SM2_Encryption_Operation final : public PK_Ops::Encryption
   {
   public:
      SM2_Encryption_Operation(const SM2_Encryption_PublicKey& key, const std::string& kdf_hash) :
         m_p_bytes(key.domain().get_curve().get_p().bytes()),
         m_order(key.domain().get_order()),
         m_base_point(key.domain().get_base_point(), m_order),
         m_public_point(key.public_point(), m_order),
         m_kdf_hash(kdf_hash)
         {}

      size_t max_input_bits() const override
         {
         // This is arbitrary, but assumes SM2 is used for key encapsulation
         return 512;
         }

      secure_vector<uint8_t> encrypt(const uint8_t msg[],
                                     size_t msg_len,
                                     RandomNumberGenerator& rng) override
         {
         std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
         std::unique_ptr<KDF> kdf = KDF::create_or_throw("KDF2(" + m_kdf_hash + ")");

         const BigInt k = BigInt::random_integer(rng, 1, m_order);

         const PointGFp C1 = m_base_point.blinded_multiply(k, rng);
         const BigInt x1 = C1.get_affine_x();
         const BigInt y1 = C1.get_affine_y();
         std::vector<uint8_t> x1_bytes(m_p_bytes);
         std::vector<uint8_t> y1_bytes(m_p_bytes);
         BigInt::encode_1363(x1_bytes.data(), x1_bytes.size(), x1);
         BigInt::encode_1363(y1_bytes.data(), y1_bytes.size(), y1);

         const PointGFp kPB = m_public_point.blinded_multiply(k, rng);

         const BigInt x2 = kPB.get_affine_x();
         const BigInt y2 = kPB.get_affine_y();
         std::vector<uint8_t> x2_bytes(m_p_bytes);
         std::vector<uint8_t> y2_bytes(m_p_bytes);
         BigInt::encode_1363(x2_bytes.data(), x2_bytes.size(), x2);
         BigInt::encode_1363(y2_bytes.data(), y2_bytes.size(), y2);

         secure_vector<uint8_t> kdf_input;
         kdf_input += x2_bytes;
         kdf_input += y2_bytes;

         const secure_vector<uint8_t> kdf_output =
            kdf->derive_key(msg_len, kdf_input.data(), kdf_input.size());

         secure_vector<uint8_t> masked_msg(msg_len);
         xor_buf(masked_msg.data(), msg, kdf_output.data(), msg_len);

         hash->update(x2_bytes);
         hash->update(msg, msg_len);
         hash->update(y2_bytes);
         std::vector<uint8_t> C3(hash->output_length());
         hash->final(C3.data());

         return DER_Encoder()
            .start_cons(SEQUENCE)
            .encode(x1)
            .encode(y1)
            .encode(C3, OCTET_STRING)
            .encode(masked_msg, OCTET_STRING)
            .end_cons()
            .get_contents();
         }

   private:
      size_t m_p_bytes;
      const BigInt& m_order;
      Blinded_Point_Multiply m_base_point;
      Blinded_Point_Multiply m_public_point;
      const std::string m_kdf_hash;
   };

class SM2_Decryption_Operation final : public PK_Ops::Decryption
   {
   public:
      SM2_Decryption_Operation(const SM2_Encryption_PrivateKey& key,
                               RandomNumberGenerator& rng,
                               const std::string& kdf_hash) :
         m_key(key),
         m_rng(rng),
         m_kdf_hash(kdf_hash)
         {}

      secure_vector<uint8_t> decrypt(uint8_t& valid_mask,
                                     const uint8_t ciphertext[],
                                     size_t ciphertext_len) override
         {
         const BigInt& cofactor = m_key.domain().get_cofactor();
         const size_t p_bytes = m_key.domain().get_curve().get_p().bytes();

         valid_mask = 0x00;

         std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
         std::unique_ptr<KDF> kdf = KDF::create_or_throw("KDF2(" + m_kdf_hash + ")");

         // Too short to be valid - no timing problem from early return
         if(ciphertext_len < 1 + p_bytes*2 + hash->output_length())
            {
            return secure_vector<uint8_t>();
            }

         BigInt x1, y1;
         secure_vector<uint8_t> C3, masked_msg;

         BER_Decoder(ciphertext, ciphertext_len)
            .start_cons(SEQUENCE)
            .decode(x1)
            .decode(y1)
            .decode(C3, OCTET_STRING)
            .decode(masked_msg, OCTET_STRING)
            .end_cons()
            .verify_end();

         const PointGFp C1(m_key.domain().get_curve(), x1, y1);
         if(!C1.on_the_curve())
            return secure_vector<uint8_t>();

         Blinded_Point_Multiply C1_mul(C1, m_key.domain().get_order());

         if(cofactor > 1 && C1_mul.blinded_multiply(cofactor, m_rng).is_zero())
            {
            return secure_vector<uint8_t>();
            }

         const PointGFp dbC1 = C1_mul.blinded_multiply(m_key.private_value(), m_rng);

         const BigInt x2 = dbC1.get_affine_x();
         const BigInt y2 = dbC1.get_affine_y();

         std::vector<uint8_t> x2_bytes(p_bytes);
         std::vector<uint8_t> y2_bytes(p_bytes);
         BigInt::encode_1363(x2_bytes.data(), x2_bytes.size(), x2);
         BigInt::encode_1363(y2_bytes.data(), y2_bytes.size(), y2);

         secure_vector<uint8_t> kdf_input;
         kdf_input += x2_bytes;
         kdf_input += y2_bytes;

         const secure_vector<uint8_t> kdf_output =
            kdf->derive_key(masked_msg.size(), kdf_input.data(), kdf_input.size());

         xor_buf(masked_msg.data(), kdf_output.data(), kdf_output.size());

         hash->update(x2_bytes);
         hash->update(masked_msg);
         hash->update(y2_bytes);
         secure_vector<uint8_t> u = hash->final();

         if(constant_time_compare(u.data(), C3.data(), hash->output_length()) == false)
            return secure_vector<uint8_t>();

         valid_mask = 0xFF;
         return masked_msg;
         }
   private:
      const SM2_Encryption_PrivateKey& m_key;
      RandomNumberGenerator& m_rng;
      const std::string m_kdf_hash;
   };

}

std::unique_ptr<PK_Ops::Encryption>
SM2_Encryption_PublicKey::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                               const std::string& params,
                                               const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      const std::string kdf_hash = (params.empty() ? "SM3" : params);
      return std::unique_ptr<PK_Ops::Encryption>(new SM2_Encryption_Operation(*this, kdf_hash));
      }

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Decryption>
SM2_Encryption_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
                                                const std::string& params,
                                                const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      const std::string kdf_hash = (params.empty() ? "SM3" : params);
      return std::unique_ptr<PK_Ops::Decryption>(new SM2_Decryption_Operation(*this, rng, kdf_hash));
      }

   throw Provider_Not_Found(algo_name(), provider);
   }

}
