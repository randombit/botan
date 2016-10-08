/*
* ECKCDSA (ISO/IEC 14888-3:2006/Cor.2:2009)
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eckcdsa.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/keypair.h>
#include <botan/reducer.h>
#include <botan/emsa.h>
#include <botan/hash.h>

namespace Botan {

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

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-1)");
   }

namespace {

/**
* ECKCDSA signature operation
*/
class ECKCDSA_Signature_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      typedef ECKCDSA_PrivateKey Key_Type;

      ECKCDSA_Signature_Operation(const ECKCDSA_PrivateKey& eckcdsa,
                                const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_order(eckcdsa.domain().get_order()),
         m_base_point(eckcdsa.domain().get_base_point(), m_order),
         m_x(eckcdsa.private_value()),
         m_mod_order(m_order),
         m_prefix()
         {
         const BigInt public_point_x = eckcdsa.public_point().get_affine_x();
         const BigInt public_point_y = eckcdsa.public_point().get_affine_y();

         m_prefix.resize(public_point_x.bytes() + public_point_y.bytes());
         public_point_x.binary_encode(m_prefix.data());
         public_point_y.binary_encode(&m_prefix[public_point_x.bytes()]);
         m_prefix.resize(HashFunction::create(hash_for_signature())->hash_block_size()); // use only the "hash input block size" leftmost bits
         }

      secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                   RandomNumberGenerator& rng) override;

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return m_order.bytes(); }
      size_t max_input_bits() const override { return m_order.bits(); }

      bool has_prefix() override { return true; }
      secure_vector<byte> message_prefix() const override { return m_prefix; }

   private:
      const BigInt& m_order;
      Blinded_Point_Multiply m_base_point;
      const BigInt& m_x;
      Modular_Reducer m_mod_order;
      secure_vector<byte> m_prefix;
   };

secure_vector<byte>
ECKCDSA_Signature_Operation::raw_sign(const byte msg[], size_t,
                                     RandomNumberGenerator& rng)
   {
   const BigInt k = BigInt::random_integer(rng, 1, m_order);
   const PointGFp k_times_P = m_base_point.blinded_multiply(k, rng);
   const BigInt k_times_P_x = k_times_P.get_affine_x();

   secure_vector<byte> to_be_hashed(k_times_P_x.bytes());
   k_times_P_x.binary_encode(to_be_hashed.data());

   std::unique_ptr<EMSA> emsa(m_emsa->clone());
   emsa->update(to_be_hashed.data(), to_be_hashed.size());
   secure_vector<byte> c = emsa->raw_data();
   c = emsa->encoding_of(c, max_input_bits(), rng);

   const BigInt r(c.data(), c.size());

   xor_buf(c, msg, c.size());
   BigInt w(c.data(), c.size());
   w = m_mod_order.reduce(w);

   const BigInt s = m_mod_order.multiply(m_x, k - w);
   BOTAN_ASSERT(s != 0, "invalid s");

   secure_vector<byte> output = BigInt::encode_1363(r, c.size());
   output += BigInt::encode_1363(s, m_mod_order.get_modulus().bytes());
   return output;
   }

/**
* ECKCDSA verification operation
*/
class ECKCDSA_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:
      typedef ECKCDSA_PublicKey Key_Type;

      ECKCDSA_Verification_Operation(const ECKCDSA_PublicKey& eckcdsa,
                                   const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_base_point(eckcdsa.domain().get_base_point()),
         m_public_point(eckcdsa.public_point()),
         m_order(eckcdsa.domain().get_order()),
         m_mod_order(m_order),
         m_prefix()
         {
         const BigInt public_point_x = m_public_point.get_affine_x();
         const BigInt public_point_y = m_public_point.get_affine_y();

         m_prefix.resize(public_point_x.bytes() + public_point_y.bytes());
         public_point_x.binary_encode(&m_prefix[0]);
         public_point_y.binary_encode(&m_prefix[public_point_x.bytes()]);
         m_prefix.resize(HashFunction::create(hash_for_signature())->hash_block_size()); // use only the "hash input block size" leftmost bits
         }

      bool has_prefix() override { return true; }
      secure_vector<byte> message_prefix() const override { return m_prefix; }

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return m_order.bytes(); }
      size_t max_input_bits() const override { return m_order.bits(); }

      bool with_recovery() const override { return false; }

      bool verify(const byte msg[], size_t msg_len,
                  const byte sig[], size_t sig_len) override;
   private:
      const PointGFp& m_base_point;
      const PointGFp& m_public_point;
      const BigInt& m_order;
      // FIXME: should be offered by curve
      Modular_Reducer m_mod_order;
      secure_vector<byte> m_prefix;
   };

bool ECKCDSA_Verification_Operation::verify(const byte msg[], size_t,
                                           const byte sig[], size_t sig_len)
   {
   // check that bit length of r is equal to output bit length of employed hash function h
   const std::unique_ptr<HashFunction> hash = HashFunction::create(hash_for_signature());

   // no way to know size of r in sig, so check that we have at least hash->output_length()+1
   // bytes in sig, enough for r and an arbitrary size s
   if(sig_len <= hash->output_length())
      {
      return false;
      }

   secure_vector<byte> r(sig, sig + hash->output_length());

   // check that 0 < s < q
   const BigInt s(sig + hash->output_length(), sig_len - hash->output_length());

   if(s <= 0 || s >= m_order)
      {
      return false;
      }

   secure_vector<byte> r_xor_e(r);
   xor_buf(r_xor_e, msg, r.size());
   BigInt w(r_xor_e.data(), r_xor_e.size());
   w = m_mod_order.reduce(w);

   const PointGFp q = (m_base_point * w) + (m_public_point * s);
   const BigInt q_x = q.get_affine_x();
   secure_vector<byte> c(q_x.bytes());
   q_x.binary_encode(c.data());
   std::unique_ptr<EMSA> emsa(m_emsa->clone());
   emsa->update(c.data(), c.size());
   secure_vector<byte> v = emsa->raw_data();
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
      return std::unique_ptr<PK_Ops::Verification>(new ECKCDSA_Verification_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
ECKCDSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                        const std::string& params,
                                        const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(new ECKCDSA_Signature_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

}
