/*
* GOST 34.10-2001 implemenation
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/gost_3410.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/reducer.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

std::vector<uint8_t> GOST_3410_PublicKey::public_key_bits() const
   {
   const BigInt x = public_point().get_affine_x();
   const BigInt y = public_point().get_affine_y();

   size_t part_size = std::max(x.bytes(), y.bytes());

   std::vector<uint8_t> bits(2*part_size);

   x.binary_encode(&bits[part_size - x.bytes()]);
   y.binary_encode(&bits[2*part_size - y.bytes()]);

   // Keys are stored in little endian format (WTF)
   for(size_t i = 0; i != part_size / 2; ++i)
      {
      std::swap(bits[i], bits[part_size-1-i]);
      std::swap(bits[part_size+i], bits[2*part_size-1-i]);
      }

   return DER_Encoder().encode(bits, OCTET_STRING).get_contents_unlocked();
   }

AlgorithmIdentifier GOST_3410_PublicKey::algorithm_identifier() const
   {
   std::vector<uint8_t> params =
      DER_Encoder().start_cons(SEQUENCE)
         .encode(OID(domain().get_oid()))
         .end_cons()
      .get_contents_unlocked();

   return AlgorithmIdentifier(get_oid(), params);
   }

GOST_3410_PublicKey::GOST_3410_PublicKey(const AlgorithmIdentifier& alg_id,
                                         const std::vector<uint8_t>& key_bits)
   {
   OID ecc_param_id;

   // The parameters also includes hash and cipher OIDs
   BER_Decoder(alg_id.parameters).start_cons(SEQUENCE).decode(ecc_param_id);

   m_domain_params = EC_Group(ecc_param_id);

   secure_vector<uint8_t> bits;
   BER_Decoder(key_bits).decode(bits, OCTET_STRING);

   const size_t part_size = bits.size() / 2;

   // Keys are stored in little endian format (WTF)
   for(size_t i = 0; i != part_size / 2; ++i)
      {
      std::swap(bits[i], bits[part_size-1-i]);
      std::swap(bits[part_size+i], bits[2*part_size-1-i]);
      }

   BigInt x(bits.data(), part_size);
   BigInt y(&bits[part_size], part_size);

   m_public_key = PointGFp(domain().get_curve(), x, y);

   BOTAN_ASSERT(m_public_key.on_the_curve(),
                "Loaded GOST 34.10 public key is on the curve");
   }

namespace {

BigInt decode_le(const uint8_t msg[], size_t msg_len)
   {
   secure_vector<uint8_t> msg_le(msg, msg + msg_len);

   for(size_t i = 0; i != msg_le.size() / 2; ++i)
      std::swap(msg_le[i], msg_le[msg_le.size()-1-i]);

   return BigInt(msg_le.data(), msg_le.size());
   }

/**
* GOST-34.10 signature operation
*/
class GOST_3410_Signature_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      GOST_3410_Signature_Operation(const GOST_3410_PrivateKey& gost_3410,
                                    const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_order(gost_3410.domain().get_order()),
         m_mod_order(m_order),
         m_base_point(gost_3410.domain().get_base_point(), m_order),
         m_x(gost_3410.private_value()) {}

      size_t max_input_bits() const override { return m_order.bits(); }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                   RandomNumberGenerator& rng) override;

   private:
      const BigInt& m_order;
      Modular_Reducer m_mod_order;
      Blinded_Point_Multiply m_base_point;
      const BigInt& m_x;
   };

secure_vector<uint8_t>
GOST_3410_Signature_Operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                        RandomNumberGenerator& rng)
   {
   BigInt k;
   do
      k.randomize(rng, m_order.bits()-1);
   while(k >= m_order);

   BigInt e = decode_le(msg, msg_len);

   e = m_mod_order.reduce(e);
   if(e == 0)
      e = 1;

   const PointGFp k_times_P = m_base_point.blinded_multiply(k, rng);
   BOTAN_ASSERT(k_times_P.on_the_curve(), "GOST 34.10 k*g is on the curve");

   const BigInt r = m_mod_order.reduce(k_times_P.get_affine_x());
   const BigInt s = m_mod_order.reduce(r*m_x + k*e);

   if(r == 0 || s == 0)
      throw Invalid_State("GOST 34.10: r == 0 || s == 0");

   secure_vector<uint8_t> output(2*m_order.bytes());
   s.binary_encode(&output[output.size() / 2 - s.bytes()]);
   r.binary_encode(&output[output.size() - r.bytes()]);
   return output;
   }

/**
* GOST-34.10 verification operation
*/
class GOST_3410_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:

      GOST_3410_Verification_Operation(const GOST_3410_PublicKey& gost,
                                       const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_base_point(gost.domain().get_base_point()),
         m_public_point(gost.public_point()),
         m_order(gost.domain().get_order()) {}

      size_t max_input_bits() const override { return m_order.bits(); }

      bool with_recovery() const override { return false; }

      bool verify(const uint8_t msg[], size_t msg_len,
                  const uint8_t sig[], size_t sig_len) override;
   private:
      const PointGFp& m_base_point;
      const PointGFp& m_public_point;
      const BigInt& m_order;
   };

bool GOST_3410_Verification_Operation::verify(const uint8_t msg[], size_t msg_len,
                                              const uint8_t sig[], size_t sig_len)
   {
   if(sig_len != m_order.bytes()*2)
      return false;

   BigInt e = decode_le(msg, msg_len);

   BigInt s(sig, sig_len / 2);
   BigInt r(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= m_order || s <= 0 || s >= m_order)
      return false;

   e %= m_order;
   if(e == 0)
      e = 1;

   BigInt v = inverse_mod(e, m_order);

   BigInt z1 = (s*v) % m_order;
   BigInt z2 = (-r*v) % m_order;

   PointGFp R = multi_exponentiate(m_base_point, z1,
                                   m_public_point, z2);

   if(R.is_zero())
     return false;

   return (R.get_affine_x() == r);
   }

}

std::unique_ptr<PK_Ops::Verification>
GOST_3410_PublicKey::create_verification_op(const std::string& params,
                                            const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Verification>(new GOST_3410_Verification_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
GOST_3410_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                          const std::string& params,
                                          const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(new GOST_3410_Signature_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

}
