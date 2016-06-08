/*
* ECDSA implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010,2015 Jack Lloyd
*     2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_utils.h>
#include <botan/ecdsa.h>
#include <botan/keypair.h>
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
  #include <botan/rfc6979.h>
#endif

namespace Botan {

bool ECDSA_PrivateKey::check_key(RandomNumberGenerator& rng,
                                 bool strong) const
   {
   if(!public_point().on_the_curve())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-1)");
   }

namespace {

/**
* ECDSA signature operation
*/
class ECDSA_Signature_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      typedef ECDSA_PrivateKey Key_Type;

      ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa,
                                const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_order(ecdsa.domain().get_order()),
         m_base_point(ecdsa.domain().get_base_point(), m_order),
         m_x(ecdsa.private_value()),
         m_mod_order(m_order),
         m_emsa(emsa)
         {
         }

      secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                   RandomNumberGenerator& rng) override;

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return m_order.bytes(); }
      size_t max_input_bits() const override { return m_order.bits(); }

   private:
      const BigInt& m_order;
      Blinded_Point_Multiply m_base_point;
      const BigInt& m_x;
      Modular_Reducer m_mod_order;
      std::string m_emsa;
   };

secure_vector<byte>
ECDSA_Signature_Operation::raw_sign(const byte msg[], size_t msg_len,
                                    RandomNumberGenerator& rng)
   {
   const BigInt m(msg, msg_len);

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   const BigInt k = generate_rfc6979_nonce(m_x, m_order, m, hash_for_deterministic_signature(m_emsa));
#else
   const BigInt k = BigInt::random_integer(rng, 1, m_order);
#endif

   const PointGFp k_times_P = m_base_point.blinded_multiply(k, rng);
   const BigInt r = m_mod_order.reduce(k_times_P.get_affine_x());
   const BigInt s = m_mod_order.multiply(inverse_mod(k, m_order), mul_add(m_x, r, m));

   // With overwhelming probability, a bug rather than actual zero r/s
   BOTAN_ASSERT(s != 0, "invalid s");
   BOTAN_ASSERT(r != 0, "invalid r");

   secure_vector<byte> output(2*m_order.bytes());
   r.binary_encode(&output[output.size() / 2 - r.bytes()]);
   s.binary_encode(&output[output.size() - s.bytes()]);
   return output;
   }

/**
* ECDSA verification operation
*/
class ECDSA_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:
      typedef ECDSA_PublicKey Key_Type;
      ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa,
                                   const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_base_point(ecdsa.domain().get_base_point()),
         m_public_point(ecdsa.public_point()),
         m_order(ecdsa.domain().get_order()),
         m_mod_order(m_order)
         {
         //m_public_point.precompute_multiples();
         }

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
   };

bool ECDSA_Verification_Operation::verify(const byte msg[], size_t msg_len,
                                          const byte sig[], size_t sig_len)
   {
   if(sig_len != m_order.bytes()*2)
      return false;

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= m_order || s <= 0 || s >= m_order)
      return false;

   BigInt w = inverse_mod(s, m_order);

   const BigInt u1 = m_mod_order.reduce(e * w);
   const BigInt u2 = m_mod_order.reduce(r * w);
   const PointGFp R = multi_exponentiate(m_base_point, u1, m_public_point, u2);

   if(R.is_zero())
      return false;

   const BigInt v = m_mod_order.reduce(R.get_affine_x());
   return (v == r);
   }

BOTAN_REGISTER_PK_SIGNATURE_OP("ECDSA", ECDSA_Signature_Operation);
BOTAN_REGISTER_PK_VERIFY_OP("ECDSA", ECDSA_Verification_Operation);

}

}
