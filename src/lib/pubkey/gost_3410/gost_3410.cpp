/*
* GOST 34.10-2012
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/gost_3410.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/reducer.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>

namespace Botan {

std::vector<uint8_t> GOST_3410_PublicKey::public_key_bits() const {
   auto bits = public_point().xy_bytes();

   const size_t part_size = bits.size() / 2;

   // GOST keys are stored in little endian format (WTF)
   for(size_t i = 0; i != part_size / 2; ++i) {
      std::swap(bits[i], bits[part_size - 1 - i]);
      std::swap(bits[part_size + i], bits[2 * part_size - 1 - i]);
   }

   std::vector<uint8_t> output;
   DER_Encoder(output).encode(bits, ASN1_Type::OctetString);
   return output;
}

std::string GOST_3410_PublicKey::algo_name() const {
   const size_t p_bits = domain().get_p_bits();

   if(p_bits == 256 || p_bits == 512) {
      return fmt("GOST-34.10-2012-{}", p_bits);
   } else {
      throw Encoding_Error("GOST-34.10-2012 is not defined for parameters of this size");
   }
}

AlgorithmIdentifier GOST_3410_PublicKey::algorithm_identifier() const {
   std::vector<uint8_t> params;

   const OID gost_oid = object_identifier();
   const OID domain_oid = domain().get_curve_oid();

   DER_Encoder(params).start_sequence().encode(domain_oid).end_cons();

   return AlgorithmIdentifier(gost_oid, params);
}

GOST_3410_PublicKey::GOST_3410_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   OID ecc_param_id;

   // The parameters also includes hash and cipher OIDs
   BER_Decoder(alg_id.parameters()).start_sequence().decode(ecc_param_id);

   m_domain_params = EC_Group::from_OID(ecc_param_id);

   const size_t p_bits = m_domain_params.get_p_bits();
   if(p_bits != 256 && p_bits != 512) {
      throw Decoding_Error(fmt("GOST-34.10-2012 is not defined for parameters of size {}", p_bits));
   }

   secure_vector<uint8_t> bits;
   BER_Decoder(key_bits).decode(bits, ASN1_Type::OctetString);

   if(bits.size() != 2 * (p_bits / 8)) {
      throw Decoding_Error("GOST-34.10-2020 invalid encoding of public key");
   }

   const size_t part_size = bits.size() / 2;

   // Keys are stored in little endian format (WTF)
   for(size_t i = 0; i != part_size / 2; ++i) {
      std::swap(bits[i], bits[part_size - 1 - i]);
      std::swap(bits[part_size + i], bits[2 * part_size - 1 - i]);
   }

   BigInt x(bits.data(), part_size);
   BigInt y(&bits[part_size], part_size);

   m_public_key = domain().point(x, y);

   BOTAN_ASSERT(m_public_key.on_the_curve(), "Loaded GOST 34.10 public key is on the curve");
}

GOST_3410_PrivateKey::GOST_3410_PrivateKey(RandomNumberGenerator& rng, const EC_Group& domain, const BigInt& x) :
      EC_PrivateKey(rng, domain, x) {
   const size_t p_bits = m_domain_params.get_p_bits();
   if(p_bits != 256 && p_bits != 512) {
      throw Decoding_Error(fmt("GOST-34.10-2012 is not defined for parameters of size {}", p_bits));
   }
}

std::unique_ptr<Public_Key> GOST_3410_PrivateKey::public_key() const {
   return std::make_unique<GOST_3410_PublicKey>(domain(), public_point());
}

namespace {

BigInt decode_le(const uint8_t msg[], size_t msg_len) {
   secure_vector<uint8_t> msg_le(msg, msg + msg_len);

   for(size_t i = 0; i != msg_le.size() / 2; ++i) {
      std::swap(msg_le[i], msg_le[msg_le.size() - 1 - i]);
   }

   return BigInt(msg_le.data(), msg_le.size());
}

/**
* GOST-34.10 signature operation
*/
class GOST_3410_Signature_Operation final : public PK_Ops::Signature_with_Hash {
   public:
      GOST_3410_Signature_Operation(const GOST_3410_PrivateKey& gost_3410, std::string_view emsa) :
            PK_Ops::Signature_with_Hash(emsa), m_group(gost_3410.domain()), m_x(gost_3410.private_value()) {}

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override;

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len, RandomNumberGenerator& rng) override;

   private:
      const EC_Group m_group;
      const BigInt m_x;
      std::vector<BigInt> m_ws;
};

AlgorithmIdentifier GOST_3410_Signature_Operation::algorithm_identifier() const {
   const std::string hash_fn = hash_function();

   const size_t p_bits = m_group.get_p_bits();

   std::string oid_name;
   if(hash_fn == "GOST-R-34.11-94") {
      oid_name = "GOST-34.10/GOST-R-34.11-94";
   } else if(hash_fn == "Streebog-256" && p_bits == 256) {
      oid_name = "GOST-34.10-2012-256/Streebog-256";
   } else if(hash_fn == "Streebog-512" && p_bits == 512) {
      oid_name = "GOST-34.10-2012-512/Streebog-512";
   } else if(hash_fn == "SHA-256" && p_bits == 256) {
      oid_name = "GOST-34.10-2012-256/SHA-256";
   }

   if(oid_name.empty()) {
      throw Not_Implemented("No encoding defined for GOST with " + hash_fn);
   }

   return AlgorithmIdentifier(oid_name, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

secure_vector<uint8_t> GOST_3410_Signature_Operation::raw_sign(const uint8_t msg[],
                                                               size_t msg_len,
                                                               RandomNumberGenerator& rng) {
   const BigInt k = m_group.random_scalar(rng);

   BigInt e = decode_le(msg, msg_len);

   e = m_group.mod_order(e);
   if(e.is_zero()) {
      e = BigInt::one();
   }

   const BigInt r = m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws));

   const BigInt s = m_group.mod_order(m_group.multiply_mod_order(r, m_x) + m_group.multiply_mod_order(k, e));

   if(r == 0 || s == 0) {
      throw Internal_Error("GOST 34.10 signature generation failed, r/s equal to zero");
   }

   return BigInt::encode_fixed_length_int_pair(s, r, m_group.get_order_bytes());
}

std::string gost_hash_from_algid(const AlgorithmIdentifier& alg_id) {
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected non-empty AlgorithmIdentifier parameters for GOST 34.10 signature");
   }

   const std::string oid_str = alg_id.oid().to_formatted_string();
   if(oid_str == "GOST-34.10/GOST-R-34.11-94") {
      return "GOST-R-34.11-94";
   }
   if(oid_str == "GOST-34.10-2012-256/Streebog-256") {
      return "Streebog-256";
   }
   if(oid_str == "GOST-34.10-2012-512/Streebog-512") {
      return "Streebog-512";
   }
   if(oid_str == "GOST-34.10-2012-256/SHA-256") {
      return "SHA-256";
   }

   throw Decoding_Error(fmt("Unknown OID ({}) for GOST 34.10 signatures", alg_id.oid()));
}

/**
* GOST-34.10 verification operation
*/
class GOST_3410_Verification_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      GOST_3410_Verification_Operation(const GOST_3410_PublicKey& gost, std::string_view padding) :
            PK_Ops::Verification_with_Hash(padding),
            m_group(gost.domain()),
            m_gy_mul(m_group.get_base_point(), gost.public_point()) {}

      GOST_3410_Verification_Operation(const GOST_3410_PublicKey& gost, const AlgorithmIdentifier& alg_id) :
            PK_Ops::Verification_with_Hash(gost_hash_from_algid(alg_id)),
            m_group(gost.domain()),
            m_gy_mul(m_group.get_base_point(), gost.public_point()) {}

      bool verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) override;

   private:
      const EC_Group m_group;
      const EC_Point_Multi_Point_Precompute m_gy_mul;
};

bool GOST_3410_Verification_Operation::verify(const uint8_t msg[],
                                              size_t msg_len,
                                              const uint8_t sig[],
                                              size_t sig_len) {
   if(sig_len != m_group.get_order_bytes() * 2) {
      return false;
   }

   const BigInt s(sig, sig_len / 2);
   const BigInt r(sig + sig_len / 2, sig_len / 2);

   const BigInt& order = m_group.get_order();

   if(r <= 0 || r >= order || s <= 0 || s >= order) {
      return false;
   }

   BigInt e = decode_le(msg, msg_len);
   e = m_group.mod_order(e);
   if(e.is_zero()) {
      e = BigInt::one();
   }

   const BigInt v = m_group.inverse_mod_order(e);

   const BigInt z1 = m_group.multiply_mod_order(s, v);
   const BigInt z2 = m_group.multiply_mod_order(-r, v);

   const EC_Point R = m_gy_mul.multi_exp(z1, z2);

   if(R.is_zero()) {
      return false;
   }

   return (R.get_affine_x() == r);
}

}  // namespace

std::unique_ptr<Private_Key> GOST_3410_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<GOST_3410_PrivateKey>(rng, domain());
}

std::unique_ptr<PK_Ops::Verification> GOST_3410_PublicKey::create_verification_op(std::string_view params,
                                                                                  std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<GOST_3410_Verification_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> GOST_3410_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<GOST_3410_Verification_Operation>(*this, signature_algorithm);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> GOST_3410_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                             std::string_view params,
                                                                             std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<GOST_3410_Signature_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
