/*
* GOST 34.10-2012
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010,2015,2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/gost_3410.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/ec_key_data.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

namespace {

EC_Group check_domain(EC_Group domain) {
   const size_t p_bits = domain.get_p_bits();
   if(p_bits != 256 && p_bits != 512) {
      throw Decoding_Error(fmt("GOST-34.10-2012 is not defined for parameters of size {}", p_bits));
   }
   return domain;
}

}  // namespace

std::vector<uint8_t> GOST_3410_PublicKey::public_key_bits() const {
   auto bits = _public_ec_point().xy_bytes();

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

   auto group = check_domain(EC_Group::from_OID(ecc_param_id));

   std::vector<uint8_t> bits;
   BER_Decoder(key_bits).decode(bits, ASN1_Type::OctetString);

   if(bits.size() != 2 * (group.get_p_bits() / 8)) {
      throw Decoding_Error("GOST-34.10-2012 invalid encoding of public key");
   }

   const size_t part_size = bits.size() / 2;

   // Keys are stored in little endian format (WTF)
   std::vector<uint8_t> encoding;
   encoding.reserve(bits.size() + 1);
   encoding.push_back(0x04);
   encoding.insert(encoding.end(), bits.rbegin() + part_size, bits.rend());
   encoding.insert(encoding.end(), bits.rbegin(), bits.rend() - part_size);

   m_public_key = std::make_shared<EC_PublicKey_Data>(std::move(group), encoding);
}

GOST_3410_PrivateKey::GOST_3410_PrivateKey(const EC_Group& domain, const BigInt& x) :
      EC_PrivateKey(check_domain(domain), EC_Scalar::from_bigint(domain, x)) {}

GOST_3410_PrivateKey::GOST_3410_PrivateKey(RandomNumberGenerator& rng, EC_Group domain) :
      EC_PrivateKey(rng, check_domain(std::move(domain))) {}

GOST_3410_PrivateKey::GOST_3410_PrivateKey(RandomNumberGenerator& rng, const EC_Group& domain, const BigInt& x) :
      EC_PrivateKey(rng, check_domain(domain), x) {}

std::unique_ptr<Public_Key> GOST_3410_PrivateKey::public_key() const {
   return std::make_unique<GOST_3410_PublicKey>(domain(), _public_ec_point());
}

namespace {

EC_Scalar gost_msg_to_scalar(const EC_Group& group, std::span<const uint8_t> msg) {
   std::vector<uint8_t> rev_bytes(msg.rbegin(), msg.rend());

   auto ie = EC_Scalar::from_bytes_mod_order(group, rev_bytes);
   if(ie.is_zero()) {
      return EC_Scalar::one(group);
   } else {
      return ie;
   }
}

/**
* GOST-34.10 signature operation
*/
class GOST_3410_Signature_Operation final : public PK_Ops::Signature_with_Hash {
   public:
      GOST_3410_Signature_Operation(const GOST_3410_PrivateKey& gost_3410, std::string_view emsa) :
            PK_Ops::Signature_with_Hash(emsa), m_group(gost_3410.domain()), m_x(gost_3410._private_key()) {}

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::vector<uint8_t> raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) override;

   private:
      const EC_Group m_group;
      const EC_Scalar m_x;
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

std::vector<uint8_t> GOST_3410_Signature_Operation::raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) {
   const auto e = gost_msg_to_scalar(m_group, msg);

   const auto k = EC_Scalar::random(m_group, rng);
   const auto r = EC_Scalar::gk_x_mod_order(k, rng, m_ws);
   const auto s = (r * m_x) + (k * e);

   if(r.is_zero() || s.is_zero()) {
      throw Internal_Error("GOST 34.10 signature generation failed, r/s equal to zero");
   }

   return EC_Scalar::serialize_pair(s, r);
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
            PK_Ops::Verification_with_Hash(padding), m_group(gost.domain()), m_gy_mul(gost._public_ec_point()) {}

      GOST_3410_Verification_Operation(const GOST_3410_PublicKey& gost, const AlgorithmIdentifier& alg_id) :
            PK_Ops::Verification_with_Hash(gost_hash_from_algid(alg_id)),
            m_group(gost.domain()),
            m_gy_mul(gost._public_ec_point()) {}

      bool verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) override;

   private:
      const EC_Group m_group;
      const EC_Group::Mul2Table m_gy_mul;
};

bool GOST_3410_Verification_Operation::verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) {
   if(auto sr = EC_Scalar::deserialize_pair(m_group, sig)) {
      const auto& [s, r] = sr.value();

      if(r.is_nonzero() && s.is_nonzero()) {
         const auto e = gost_msg_to_scalar(m_group, msg);

         const auto v = e.invert_vartime();

         // Check if r == x_coord(g*v*s - y*v*r) % n
         return m_gy_mul.mul2_vartime_x_mod_order_eq(r, v, s, r.negate());
      }
   }

   return false;
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
