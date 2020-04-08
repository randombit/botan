/*
* GOST 34.10-2012
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/gost_3410.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>
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

   std::vector<uint8_t> output;
   DER_Encoder(output).encode(bits, OCTET_STRING);
   return output;
   }

std::string GOST_3410_PublicKey::algo_name() const
   {
   const size_t p_bits = domain().get_p_bits();

   if(p_bits == 256 || p_bits == 512)
      return "GOST-34.10-2012-" + std::to_string(p_bits);
   else
      throw Encoding_Error("GOST-34.10-2012 is not defined for parameters of this size");
   }

AlgorithmIdentifier GOST_3410_PublicKey::algorithm_identifier() const
   {
   std::vector<uint8_t> params;

   const OID gost_oid = get_oid();
   const OID domain_oid = domain().get_curve_oid();

   DER_Encoder(params).start_cons(SEQUENCE).encode(domain_oid).end_cons();

   return AlgorithmIdentifier(gost_oid, params);
   }

GOST_3410_PublicKey::GOST_3410_PublicKey(const AlgorithmIdentifier& alg_id,
                                         const std::vector<uint8_t>& key_bits)
   {
   OID ecc_param_id;

   // The parameters also includes hash and cipher OIDs
   BER_Decoder(alg_id.get_parameters()).start_cons(SEQUENCE).decode(ecc_param_id);

   m_domain_params = EC_Group(ecc_param_id);

   const size_t p_bits = m_domain_params.get_p_bits();
   if(p_bits != 256 && p_bits != 512)
      throw Decoding_Error("GOST-34.10-2012 is not defined for parameters of size " +
                           std::to_string(p_bits));

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

   m_public_key = domain().point(x, y);

   BOTAN_ASSERT(m_public_key.on_the_curve(),
                "Loaded GOST 34.10 public key is on the curve");
   }

GOST_3410_PrivateKey::GOST_3410_PrivateKey(RandomNumberGenerator& rng,
                                           const EC_Group& domain,
                                           const BigInt& x) :
   EC_PrivateKey(rng, domain, x)
   {
   const size_t p_bits = m_domain_params.get_p_bits();
   if(p_bits != 256 && p_bits != 512)
      throw Decoding_Error("GOST-34.10-2012 is not defined for parameters of size " +
                           std::to_string(p_bits));
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
class GOST_3410_Signature_Operation final : public PK_Ops::Signature_with_EMSA
   {
   public:
      GOST_3410_Signature_Operation(const GOST_3410_PrivateKey& gost_3410,
                                    const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_group(gost_3410.domain()),
         m_x(gost_3410.private_value())
         {}

      size_t signature_length() const override { return 2*m_group.get_order_bytes(); }

      size_t max_input_bits() const override { return m_group.get_order_bits(); }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                      RandomNumberGenerator& rng) override;

   private:
      const EC_Group m_group;
      const BigInt& m_x;
      std::vector<BigInt> m_ws;
   };

secure_vector<uint8_t>
GOST_3410_Signature_Operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                        RandomNumberGenerator& rng)
   {
   const BigInt k = m_group.random_scalar(rng);

   BigInt e = decode_le(msg, msg_len);

   e = m_group.mod_order(e);
   if(e == 0)
      e = 1;

   const BigInt r = m_group.mod_order(
      m_group.blinded_base_point_multiply_x(k, rng, m_ws));

   const BigInt s = m_group.mod_order(
      m_group.multiply_mod_order(r, m_x) +
      m_group.multiply_mod_order(k, e));

   if(r == 0 || s == 0)
      throw Internal_Error("GOST 34.10 signature generation failed, r/s equal to zero");

   return BigInt::encode_fixed_length_int_pair(s, r, m_group.get_order_bytes());
   }

/**
* GOST-34.10 verification operation
*/
class GOST_3410_Verification_Operation final : public PK_Ops::Verification_with_EMSA
   {
   public:

      GOST_3410_Verification_Operation(const GOST_3410_PublicKey& gost,
                                       const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_group(gost.domain()),
         m_gy_mul(m_group.get_base_point(), gost.public_point())
         {}

      size_t max_input_bits() const override { return m_group.get_order_bits(); }

      bool with_recovery() const override { return false; }

      bool verify(const uint8_t msg[], size_t msg_len,
                  const uint8_t sig[], size_t sig_len) override;
   private:
      const EC_Group m_group;
      const PointGFp_Multi_Point_Precompute m_gy_mul;
   };

bool GOST_3410_Verification_Operation::verify(const uint8_t msg[], size_t msg_len,
                                              const uint8_t sig[], size_t sig_len)
   {
   if(sig_len != m_group.get_order_bytes() * 2)
      return false;

   const BigInt s(sig, sig_len / 2);
   const BigInt r(sig + sig_len / 2, sig_len / 2);

   const BigInt& order = m_group.get_order();

   if(r <= 0 || r >= order || s <= 0 || s >= order)
      return false;

   BigInt e = decode_le(msg, msg_len);
   e = m_group.mod_order(e);
   if(e == 0)
      e = 1;

   const BigInt v = m_group.inverse_mod_order(e);

   const BigInt z1 = m_group.multiply_mod_order(s, v);
   const BigInt z2 = m_group.multiply_mod_order(-r, v);

   const PointGFp R = m_gy_mul.multi_exp(z1, z2);

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
