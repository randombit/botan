/*
* ECKCDSA (ISO/IEC 14888-3:2006/Cor.2:2009)
* (C) 2016 René Korthaus, Sirrix AG
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eckcdsa.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>
#include <botan/internal/keypair.h>
#include <botan/reducer.h>
#include <botan/internal/emsa.h>
#include <botan/hash.h>
#include <botan/rng.h>

namespace Botan {

std::unique_ptr<Public_Key> ECKCDSA_PrivateKey::public_key() const
   {
   return std::make_unique<ECKCDSA_PublicKey>(domain(), public_point());
   }

bool ECKCDSA_PrivateKey::check_key(RandomNumberGenerator& rng,
                                   bool strong) const
   {
   if(!public_point().on_the_curve())
      {
      return false;
      }

   if(!strong)
      {
      return true;
      }

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
   }

namespace {

/**
* ECKCDSA signature operation
*/
class ECKCDSA_Signature_Operation final : public PK_Ops::Signature
   {
   public:

      ECKCDSA_Signature_Operation(const ECKCDSA_PrivateKey& eckcdsa,
                                  const std::string& emsa) :
         m_group(eckcdsa.domain()),
         m_x(eckcdsa.private_value()),
         m_emsa(EMSA::create_or_throw(emsa)),
         m_hash(hash_for_emsa(emsa)),
         m_prefix_used(false)
         {
         if(m_emsa->requires_message_recovery())
            {
            throw Invalid_Argument("Signature padding method " + emsa +
                                   " requires message recovery, which is not supported by ECKCDSA");
            }

         auto hash = HashFunction::create_or_throw(m_hash);

         /*
         ECKCDSA does support hash truncation but for whatever reason uses the
         opposite convention of DSA, ECDSA, ECGDSA, etc, cutting bits from
         the low rather than the high side of the hash.

         As a result it is not easily supported in this codebase, and since
         ECKCDSA is quite obscure and mostly included for BSI compliance, we
         simply prohibit creating signatures where the resulting signature will
         not be accepted by other implementations of ECKCDSA

         See https://github.com/randombit/botan/issues/2742 for further detail.
         */

         if(hash->output_length() > m_group.get_order_bytes())
            throw Encoding_Error("ECKCDSA does not support the hash being larger than the group");

         const BigInt public_point_x = eckcdsa.public_point().get_affine_x();
         const BigInt public_point_y = eckcdsa.public_point().get_affine_y();

         const size_t order_bytes = m_group.get_order_bytes();

         m_prefix.resize(2*order_bytes);
         BigInt::encode_1363(&m_prefix[0], order_bytes, public_point_x);
         BigInt::encode_1363(&m_prefix[order_bytes], order_bytes, public_point_y);

         // Either truncate or zero-extend to match the hash block size
         m_prefix.resize(hash->hash_block_size());
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         if(!m_prefix_used)
            {
            m_emsa->update(m_prefix.data(), m_prefix.size());
            m_prefix_used = true;
            }
         m_emsa->update(msg, msg_len);
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override
         {
         m_prefix_used = false;
         const secure_vector<uint8_t> msg = m_emsa->raw_data();
         const auto padded = m_emsa->encoding_of(msg, this->max_input_bits(), rng);
         return raw_sign(padded.data(), padded.size(), rng);
         }

      size_t signature_length() const override { return 2*m_group.get_order_bytes(); }

   private:
      size_t max_input_bits() const { return m_group.get_order_bits(); }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                      RandomNumberGenerator& rng);

      const EC_Group m_group;
      const BigInt& m_x;
      std::unique_ptr<EMSA> m_emsa;
      const std::string m_hash;
      secure_vector<uint8_t> m_prefix;
      std::vector<BigInt> m_ws;
      bool m_prefix_used;
   };

secure_vector<uint8_t>
ECKCDSA_Signature_Operation::raw_sign(const uint8_t msg[], size_t /*msg_len*/,
                                      RandomNumberGenerator& rng)
   {
   const BigInt k = m_group.random_scalar(rng);
   const BigInt k_times_P_x = m_group.blinded_base_point_multiply_x(k, rng, m_ws);

   secure_vector<uint8_t> to_be_hashed(k_times_P_x.bytes());
   k_times_P_x.binary_encode(to_be_hashed.data());

   std::unique_ptr<EMSA> emsa = m_emsa->new_object();
   emsa->update(to_be_hashed.data(), to_be_hashed.size());
   secure_vector<uint8_t> c = emsa->raw_data();
   c = emsa->encoding_of(c, max_input_bits(), rng);

   const BigInt r(c.data(), c.size());

   xor_buf(c, msg, c.size());
   BigInt w(c.data(), c.size());
   w = m_group.mod_order(w);

   const BigInt s = m_group.multiply_mod_order(m_x, k - w);
   if(s.is_zero())
      throw Internal_Error("During ECKCDSA signature generation created zero s");

   secure_vector<uint8_t> output = BigInt::encode_1363(r, c.size());
   output += BigInt::encode_1363(s, m_group.get_order_bytes());
   return output;
   }

/**
* ECKCDSA verification operation
*/
class ECKCDSA_Verification_Operation final : public PK_Ops::Verification
   {
   public:

      ECKCDSA_Verification_Operation(const ECKCDSA_PublicKey& eckcdsa,
                                     const std::string& emsa) :
         m_group(eckcdsa.domain()),
         m_gy_mul(m_group.get_base_point(), eckcdsa.public_point()),
         m_emsa(EMSA::create_or_throw(emsa)),
         m_hash(hash_for_emsa(emsa)),
         m_prefix_used(false)
         {
         const BigInt public_point_x = eckcdsa.public_point().get_affine_x();
         const BigInt public_point_y = eckcdsa.public_point().get_affine_y();

         const size_t order_bytes = m_group.get_order_bytes();

         m_prefix.resize(2*order_bytes);
         BigInt::encode_1363(&m_prefix[0], order_bytes, public_point_x);
         BigInt::encode_1363(&m_prefix[order_bytes], order_bytes, public_point_y);

         const size_t block_size = HashFunction::create(m_hash)->hash_block_size();
         // Either truncate or zero-extend to match the hash block size
         m_prefix.resize(block_size);
         }

      void update(const uint8_t msg[], size_t msg_len) override;

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override;
   private:
      size_t max_input_bits() const { return m_group.get_order_bits(); }

      bool verify(const uint8_t msg[], size_t msg_len,
                  const uint8_t sig[], size_t sig_len);

      const EC_Group m_group;
      const EC_Point_Multi_Point_Precompute m_gy_mul;
      secure_vector<uint8_t> m_prefix;
      std::unique_ptr<EMSA> m_emsa;
      const std::string m_hash;
      bool m_prefix_used;
   };

void ECKCDSA_Verification_Operation::update(const uint8_t msg[], size_t msg_len)
   {
   if(!m_prefix_used)
      {
      m_prefix_used = true;
      m_emsa->update(m_prefix.data(), m_prefix.size());
      }
   m_emsa->update(msg, msg_len);
   }

bool ECKCDSA_Verification_Operation::is_valid_signature(const uint8_t sig[], size_t sig_len)
   {
   m_prefix_used = false;
   const secure_vector<uint8_t> msg = m_emsa->raw_data();

   Null_RNG rng;
   secure_vector<uint8_t> encoded = m_emsa->encoding_of(msg, max_input_bits(), rng);
   return verify(encoded.data(), encoded.size(), sig, sig_len);
   }

bool ECKCDSA_Verification_Operation::verify(const uint8_t msg[], size_t /*msg_len*/,
                                            const uint8_t sig[], size_t sig_len)
   {
   const std::unique_ptr<HashFunction> hash = HashFunction::create(m_hash);
   //calculate size of r

   const size_t order_bytes = m_group.get_order_bytes();

   const size_t size_r = std::min(hash -> output_length(), order_bytes);
   if(sig_len != size_r + order_bytes)
      {
      return false;
      }

   secure_vector<uint8_t> r(sig, sig + size_r);

   // check that 0 < s < q
   const BigInt s(sig + size_r, order_bytes);

   if(s <= 0 || s >= m_group.get_order())
      {
      return false;
      }

   secure_vector<uint8_t> r_xor_e(r);
   xor_buf(r_xor_e, msg, r.size());
   BigInt w(r_xor_e.data(), r_xor_e.size());
   w = m_group.mod_order(w);

   const EC_Point q = m_gy_mul.multi_exp(w, s);
   if(q.is_zero())
      {
      return false;
      }

   const BigInt q_x = q.get_affine_x();
   secure_vector<uint8_t> c(q_x.bytes());
   q_x.binary_encode(c.data());
   std::unique_ptr<EMSA> emsa = m_emsa->new_object();
   emsa->update(c.data(), c.size());
   secure_vector<uint8_t> v = emsa->raw_data();
   Null_RNG rng;
   v = emsa->encoding_of(v, max_input_bits(), rng);

   return (v == r);
   }

}

std::unique_ptr<PK_Ops::Verification>
ECKCDSA_PublicKey::create_verification_op(const std::string& params,
                                          const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::make_unique<ECKCDSA_Verification_Operation>(*this, params);
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
ECKCDSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                        const std::string& params,
                                        const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::make_unique<ECKCDSA_Signature_Operation>(*this, params);
   throw Provider_Not_Found(algo_name(), provider);
   }

}
