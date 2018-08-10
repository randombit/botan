/*
* SM2 Encryption
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm2.h>
#include <botan/internal/point_mul.h>
#include <botan/pk_ops.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/kdf.h>
#include <botan/hash.h>

namespace Botan {

namespace {

class SM2_Encryption_Operation final : public PK_Ops::Encryption
   {
   public:
      SM2_Encryption_Operation(const SM2_Encryption_PublicKey& key,
                               RandomNumberGenerator& rng,
                               const std::string& kdf_hash) :
         m_group(key.domain()),
         m_kdf_hash(kdf_hash),
         m_ws(PointGFp::WORKSPACE_SIZE),
         m_mul_public_point(key.public_point(), rng, m_ws)
         {
         std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
         m_hash_size = hash->output_length();
         }

      size_t max_input_bits() const override
         {
         // This is arbitrary, but assumes SM2 is used for key encapsulation
         return 512;
         }

      size_t ciphertext_length(size_t ptext_len) const override
         {
         const size_t elem_size = m_group.get_order_bytes();
         const size_t der_overhead = 16;

         return der_overhead + 2*elem_size + m_hash_size + ptext_len;
         }

      secure_vector<uint8_t> encrypt(const uint8_t msg[],
                                     size_t msg_len,
                                     RandomNumberGenerator& rng) override
         {
         std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
         std::unique_ptr<KDF> kdf = KDF::create_or_throw("KDF2(" + m_kdf_hash + ")");

         const size_t p_bytes = m_group.get_p_bytes();

         const BigInt k = m_group.random_scalar(rng);

         const PointGFp C1 = m_group.blinded_base_point_multiply(k, rng, m_ws);
         const BigInt x1 = C1.get_affine_x();
         const BigInt y1 = C1.get_affine_y();
         std::vector<uint8_t> x1_bytes(p_bytes);
         std::vector<uint8_t> y1_bytes(p_bytes);
         BigInt::encode_1363(x1_bytes.data(), x1_bytes.size(), x1);
         BigInt::encode_1363(y1_bytes.data(), y1_bytes.size(), y1);

         const PointGFp kPB = m_mul_public_point.mul(k, rng, m_group.get_order(), m_ws);

         const BigInt x2 = kPB.get_affine_x();
         const BigInt y2 = kPB.get_affine_y();
         std::vector<uint8_t> x2_bytes(p_bytes);
         std::vector<uint8_t> y2_bytes(p_bytes);
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
      const EC_Group m_group;
      const std::string m_kdf_hash;

      std::vector<BigInt> m_ws;
      PointGFp_Var_Point_Precompute m_mul_public_point;
      size_t m_hash_size;
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
         {
         std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
         m_hash_size = hash->output_length();
         }

      size_t plaintext_length(size_t ptext_len) const override
         {
         /*
         * This ignores the DER encoding and so overestimates the
         * plaintext length by 12 bytes or so
         */
         const size_t elem_size = m_key.domain().get_order_bytes();

         if(ptext_len < 2*elem_size + m_hash_size)
            return 0;

         return ptext_len - (2*elem_size + m_hash_size);
         }

      secure_vector<uint8_t> decrypt(uint8_t& valid_mask,
                                     const uint8_t ciphertext[],
                                     size_t ciphertext_len) override
         {
         const EC_Group& group = m_key.domain();
         const BigInt& cofactor = group.get_cofactor();
         const size_t p_bytes = group.get_p_bytes();

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

         std::vector<uint8_t> recode_ctext;
         DER_Encoder(recode_ctext)
            .start_cons(SEQUENCE)
            .encode(x1)
            .encode(y1)
            .encode(C3, OCTET_STRING)
            .encode(masked_msg, OCTET_STRING)
            .end_cons();

         if(recode_ctext.size() != ciphertext_len)
            return secure_vector<uint8_t>();

         if(same_mem(recode_ctext.data(), ciphertext, ciphertext_len) == false)
            return secure_vector<uint8_t>();

         PointGFp C1 = group.point(x1, y1);
         C1.randomize_repr(m_rng);

         // Here C1 is publically invalid, so no problem with early return:
         if(!C1.on_the_curve())
            return secure_vector<uint8_t>();

         if(cofactor > 1 && (C1 * cofactor).is_zero())
            {
            return secure_vector<uint8_t>();
            }

         const PointGFp dbC1 = group.blinded_var_point_multiply(
            C1, m_key.private_value(), m_rng, m_ws);

         const BigInt x2 = dbC1.get_affine_x();
         const BigInt y2 = dbC1.get_affine_y();

         secure_vector<uint8_t> x2_bytes(p_bytes);
         secure_vector<uint8_t> y2_bytes(p_bytes);
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
      std::vector<BigInt> m_ws;
      size_t m_hash_size;
   };

}

std::unique_ptr<PK_Ops::Encryption>
SM2_PublicKey::create_encryption_op(RandomNumberGenerator& rng,
                                    const std::string& params,
                                    const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      const std::string kdf_hash = (params.empty() ? "SM3" : params);
      return std::unique_ptr<PK_Ops::Encryption>(new SM2_Encryption_Operation(*this, rng, kdf_hash));
      }

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Decryption>
SM2_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
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
