/*
* ECGDSA (BSI-TR-03111, version 2.0)
* (C) 2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_utils.h>
#include <botan/ecgdsa.h>
#include <botan/keypair.h>

namespace Botan {

bool ECGDSA_PrivateKey::check_key(RandomNumberGenerator& rng,
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
* ECGDSA signature operation
*/
class ECGDSA_Signature_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      typedef ECGDSA_PrivateKey Key_Type;

      ECGDSA_Signature_Operation(const ECGDSA_PrivateKey& ecgdsa,
                                const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_order(ecgdsa.domain().get_order()),
         m_base_point(ecgdsa.domain().get_base_point(), m_order),
         m_x(ecgdsa.private_value()),
         m_mod_order(m_order)
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
   };

secure_vector<byte>
ECGDSA_Signature_Operation::raw_sign(const byte msg[], size_t msg_len,
                                     RandomNumberGenerator& rng)
   {
   const BigInt m(msg, msg_len);

   BigInt k = BigInt::random_integer(rng, 1, m_order);

   const PointGFp k_times_P = m_base_point.blinded_multiply(k, rng);
   const BigInt r = m_mod_order.reduce(k_times_P.get_affine_x());
   const BigInt s = m_mod_order.multiply(m_x, mul_sub(k, r, m));

   // With overwhelming probability, a bug rather than actual zero r/s
   BOTAN_ASSERT(s != 0, "invalid s");
   BOTAN_ASSERT(r != 0, "invalid r");

   secure_vector<byte> output(2*m_order.bytes());
   r.binary_encode(&output[output.size() / 2 - r.bytes()]);
   s.binary_encode(&output[output.size() - s.bytes()]);
   return output;
   }

/**
* ECGDSA verification operation
*/
class ECGDSA_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:
      typedef ECGDSA_PublicKey Key_Type;

      ECGDSA_Verification_Operation(const ECGDSA_PublicKey& ecgdsa,
                                   const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_base_point(ecgdsa.domain().get_base_point()),
         m_public_point(ecgdsa.public_point()),
         m_order(ecgdsa.domain().get_order()),
         m_mod_order(m_order)
         {
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

bool ECGDSA_Verification_Operation::verify(const byte msg[], size_t msg_len,
                                           const byte sig[], size_t sig_len)
   {
   if(sig_len != m_order.bytes()*2)
      return false;

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= m_order || s <= 0 || s >= m_order)
      return false;

   BigInt w = inverse_mod(r, m_order);

   const BigInt u1 = m_mod_order.reduce(e * w);
   const BigInt u2 = m_mod_order.reduce(s * w);
   const PointGFp R = multi_exponentiate(m_base_point, u1, m_public_point, u2);

   if(R.is_zero())
      return false;

   const BigInt v = m_mod_order.reduce(R.get_affine_x());
   return (v == r);
   }

BOTAN_REGISTER_PK_SIGNATURE_OP("ECGDSA", ECGDSA_Signature_Operation);
BOTAN_REGISTER_PK_VERIFY_OP("ECGDSA", ECGDSA_Verification_Operation);

}

}
