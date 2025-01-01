/*
* SM2 Encryption
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm2.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/pk_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

class SM2_Encryption_Operation final : public PK_Ops::Encryption {
   public:
      SM2_Encryption_Operation(const SM2_Encryption_PublicKey& key, std::string_view kdf_hash) :
            m_group(key.domain()), m_peer(key._public_ec_point()) {
         m_hash = HashFunction::create_or_throw(kdf_hash);
         m_kdf = KDF::create_or_throw(fmt("KDF2({})", kdf_hash));
      }

      size_t max_input_bits() const override {
         // This is arbitrary, but assumes SM2 is used for key encapsulation
         return 512;
      }

      size_t ciphertext_length(size_t ptext_len) const override {
         const size_t elem_size = m_group.get_order_bytes();
         const size_t der_overhead = 16;

         return der_overhead + 2 * elem_size + m_hash->output_length() + ptext_len;
      }

      std::vector<uint8_t> encrypt(std::span<const uint8_t> msg, RandomNumberGenerator& rng) override {
         const auto k = EC_Scalar::random(m_group, rng);

         const EC_AffinePoint C1 = EC_AffinePoint::g_mul(k, rng, m_ws);

         const EC_AffinePoint kPB = m_peer.mul(k, rng, m_ws);

         const auto x2_bytes = kPB.x_bytes();
         const auto y2_bytes = kPB.y_bytes();

         secure_vector<uint8_t> kdf_input;
         kdf_input += x2_bytes;
         kdf_input += y2_bytes;

         const auto kdf_output = m_kdf->derive_key(msg.size(), kdf_input);

         std::vector<uint8_t> masked_msg(msg.size());
         xor_buf(masked_msg, msg, kdf_output);

         m_hash->update(x2_bytes);
         m_hash->update(msg);
         m_hash->update(y2_bytes);
         const auto C3 = m_hash->final<std::vector<uint8_t>>();

         std::vector<uint8_t> ctext;
         DER_Encoder(ctext)
            .start_sequence()
            .encode(BigInt(C1.x_bytes()))
            .encode(BigInt(C1.y_bytes()))
            .encode(C3, ASN1_Type::OctetString)
            .encode(masked_msg, ASN1_Type::OctetString)
            .end_cons();

         return ctext;
      }

   private:
      const EC_Group m_group;
      const EC_AffinePoint m_peer;
      std::unique_ptr<HashFunction> m_hash;
      std::unique_ptr<KDF> m_kdf;
      std::vector<BigInt> m_ws;
};

class SM2_Decryption_Operation final : public PK_Ops::Decryption {
   public:
      SM2_Decryption_Operation(const SM2_Encryption_PrivateKey& key,
                               RandomNumberGenerator& rng,
                               std::string_view kdf_hash) :
            m_group(key.domain()), m_x(key._private_key()), m_rng(rng) {
         m_hash = HashFunction::create_or_throw(kdf_hash);

         const std::string kdf_name = fmt("KDF2({})", kdf_hash);
         m_kdf = KDF::create_or_throw(kdf_name);
      }

      size_t plaintext_length(size_t ptext_len) const override {
         /*
         * This ignores the DER encoding and so overestimates the
         * plaintext length by 12 bytes or so
         */
         const size_t elem_size = m_group.get_order_bytes();

         if(ptext_len < 2 * elem_size + m_hash->output_length()) {
            return 0;
         }

         return ptext_len - (2 * elem_size + m_hash->output_length());
      }

      secure_vector<uint8_t> decrypt(uint8_t& valid_mask, std::span<const uint8_t> ctext) override {
         const size_t p_bytes = m_group.get_p_bytes();

         valid_mask = 0x00;

         // Too short to be valid - no timing problem from early return
         if(ctext.size() < 1 + p_bytes * 2 + m_hash->output_length()) {
            return secure_vector<uint8_t>();
         }

         BigInt x1, y1;
         secure_vector<uint8_t> C3, masked_msg;

         BER_Decoder(ctext)
            .start_sequence()
            .decode(x1)
            .decode(y1)
            .decode(C3, ASN1_Type::OctetString)
            .decode(masked_msg, ASN1_Type::OctetString)
            .end_cons()
            .verify_end();

         std::vector<uint8_t> recode_ctext;
         DER_Encoder(recode_ctext)
            .start_sequence()
            .encode(x1)
            .encode(y1)
            .encode(C3, ASN1_Type::OctetString)
            .encode(masked_msg, ASN1_Type::OctetString)
            .end_cons();

         if(recode_ctext.size() != ctext.size()) {
            return secure_vector<uint8_t>();
         }

         if(CT::is_equal(recode_ctext.data(), ctext.data(), ctext.size()).as_bool() == false) {
            return secure_vector<uint8_t>();
         }

         auto C1 = EC_AffinePoint::from_bigint_xy(m_group, x1, y1);

         // Here C1 is publically invalid, so no problem with early return:
         if(!C1) {
            return secure_vector<uint8_t>();
         }

         const auto dbC1 = C1->mul(m_x, m_rng, m_ws);
         const auto x2_bytes = dbC1.x_bytes();
         const auto y2_bytes = dbC1.y_bytes();

         const auto kdf_output = m_kdf->derive_key(masked_msg.size(), dbC1.xy_bytes());

         xor_buf(masked_msg.data(), kdf_output.data(), kdf_output.size());

         m_hash->update(x2_bytes);
         m_hash->update(masked_msg);
         m_hash->update(y2_bytes);
         const auto u = m_hash->final();

         if(!CT::is_equal(u.data(), C3.data(), m_hash->output_length()).as_bool()) {
            return secure_vector<uint8_t>();
         }

         valid_mask = 0xFF;
         return masked_msg;
      }

   private:
      const EC_Group m_group;
      const EC_Scalar m_x;
      RandomNumberGenerator& m_rng;
      std::vector<BigInt> m_ws;
      std::unique_ptr<HashFunction> m_hash;
      std::unique_ptr<KDF> m_kdf;
};

}  // namespace

std::unique_ptr<PK_Ops::Encryption> SM2_PublicKey::create_encryption_op(RandomNumberGenerator& rng,
                                                                        std::string_view params,
                                                                        std::string_view provider) const {
   BOTAN_UNUSED(rng);

   if(provider == "base" || provider.empty()) {
      if(params.empty()) {
         return std::make_unique<SM2_Encryption_Operation>(*this, "SM3");
      } else {
         return std::make_unique<SM2_Encryption_Operation>(*this, params);
      }
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Decryption> SM2_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
                                                                         std::string_view params,
                                                                         std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(params.empty()) {
         return std::make_unique<SM2_Decryption_Operation>(*this, rng, "SM3");
      } else {
         return std::make_unique<SM2_Decryption_Operation>(*this, rng, params);
      }
   }

   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
