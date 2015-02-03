/*
* ECDSA implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_utils.h>
#include <botan/ecdsa.h>
#include <botan/reducer.h>
#include <botan/keypair.h>
#include <botan/rfc6979.h>

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
class ECDSA_Signature_Operation : public PK_Ops::Signature
   {
   public:
      typedef ECDSA_PrivateKey Key_Type;

      ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa,
                                const std::string& emsa) :
         base_point(ecdsa.domain().get_base_point()),
         order(ecdsa.domain().get_order()),
         x(ecdsa.private_value()),
         mod_order(order),
         m_hash(hash_for_deterministic_signature(emsa))
         {
         }

      secure_vector<byte> sign(const byte msg[], size_t msg_len,
                              RandomNumberGenerator& rng);

      size_t message_parts() const { return 2; }
      size_t message_part_size() const { return order.bytes(); }
      size_t max_input_bits() const { return order.bits(); }

   private:
      const PointGFp& base_point;
      const BigInt& order;
      const BigInt& x;
      Modular_Reducer mod_order;
      std::string m_hash;
   };

secure_vector<byte>
ECDSA_Signature_Operation::sign(const byte msg[], size_t msg_len,
                                RandomNumberGenerator&)
   {
   const BigInt m(msg, msg_len);

   const BigInt k = generate_rfc6979_nonce(x, order, m, m_hash);

   const PointGFp k_times_P = base_point * k;
   const BigInt r = mod_order.reduce(k_times_P.get_affine_x());
   const BigInt s = mod_order.multiply(inverse_mod(k, order), mul_add(x, r, m));

   // With overwhelming probability, a bug rather than actual zero r/s
   BOTAN_ASSERT(s != 0, "invalid s");
   BOTAN_ASSERT(r != 0, "invalid r");

   secure_vector<byte> output(2*order.bytes());
   r.binary_encode(&output[output.size() / 2 - r.bytes()]);
   s.binary_encode(&output[output.size() - s.bytes()]);
   return output;
   }

/**
* ECDSA verification operation
*/
class ECDSA_Verification_Operation : public PK_Ops::Verification
   {
   public:
      typedef ECDSA_PublicKey Key_Type;
      ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa,
                                   const std::string&) :
         base_point(ecdsa.domain().get_base_point()),
         public_point(ecdsa.public_point()),
         order(ecdsa.domain().get_order())
         {
         }

      size_t message_parts() const { return 2; }
      size_t message_part_size() const { return order.bytes(); }
      size_t max_input_bits() const { return order.bits(); }

      bool with_recovery() const { return false; }

      bool verify(const byte msg[], size_t msg_len,
                  const byte sig[], size_t sig_len);
   private:
      const PointGFp& base_point;
      const PointGFp& public_point;
      const BigInt& order;
   };

bool ECDSA_Verification_Operation::verify(const byte msg[], size_t msg_len,
                                          const byte sig[], size_t sig_len)
   {
   if(sig_len != order.bytes()*2)
      return false;

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= order || s <= 0 || s >= order)
      return false;

   BigInt w = inverse_mod(s, order);

   PointGFp R = w * multi_exponentiate(base_point, e,
                                       public_point, r);

   if(R.is_zero())
      return false;

   return (R.get_affine_x() % order == r);
   }

BOTAN_REGISTER_PK_SIGNATURE_OP("ECDSA", ECDSA_Signature_Operation);
BOTAN_REGISTER_PK_VERIFY_OP("ECDSA", ECDSA_Verification_Operation);

}

}
