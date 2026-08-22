/*
* SM2 Signatures
* (C) 2017,2018 Ribose Inc
* (C) 2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm2.h>

#include <botan/ec_group.h>
#include <botan/hash.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keypair.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/parsing.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/pk_options_impl.h>

namespace Botan {

std::string SM2_PublicKey::algo_name() const {
   return "SM2";
}

namespace {

const AlgorithmIdentifier& assert_sm2_algorithm_identifier(const AlgorithmIdentifier& alg_id) {
   const auto alg_name = alg_id.oid().registered_name();
   // OpenSSL uses ECDSA's OID for SM2
   if(alg_name != "SM2" && alg_name != "SM2_Enc" && alg_name != "ECDSA") {
      throw Decoding_Error(fmt("Unexpected AlgorithmIdentifier OID {} in association with SM2 key", alg_id.oid()));
   }

   return alg_id;  // NOLINT(*-return-const-ref-from-parameter)
}

}  // namespace

SM2_PublicKey::SM2_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      EC_PublicKey(assert_sm2_algorithm_identifier(alg_id), key_bits) {}

std::optional<size_t> SM2_PublicKey::_signature_element_size_for_DER_encoding() const {
   return domain().get_order_bytes();
}

std::unique_ptr<Public_Key> SM2_PrivateKey::public_key() const {
   return std::make_unique<SM2_Signature_PublicKey>(domain(), _public_ec_point());
}

bool SM2_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!EC_PrivateKey::check_key(rng, strong)) {
      return false;
   }

   // SM2 has an oddity in private key generation when compared to
   // other EC*DSA style signature algorithms described in ISO14888-3:
   // the private key x MUST be in [0, q-1) instead of [0, q).
   //
   // The lower bound is already checked by the default impl
   if(private_value() >= domain().get_order() - 1) {
      return false;
   }

   if(!strong) {
      return true;
   }

   return KeyPair::signature_consistency_check(rng, *this, "user@example.com,SM3");
}

SM2_PrivateKey::SM2_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      EC_PrivateKey(assert_sm2_algorithm_identifier(alg_id), key_bits),
      m_da_inv((this->_private_key() + EC_Scalar::one(domain())).invert()),
      m_da_inv_legacy(m_da_inv.to_bigint()) {
   if(m_da_inv.is_zero()) {
      throw Decoding_Error("SM2 private key cannot equal n-1");
   }
}

SM2_PrivateKey::SM2_PrivateKey(const EC_Group& group, const EC_Scalar& x) :
      EC_PrivateKey(group, x),
      m_da_inv((this->_private_key() + EC_Scalar::one(domain())).invert()),
      m_da_inv_legacy(m_da_inv.to_bigint()) {
   BOTAN_ARG_CHECK(m_da_inv.is_nonzero(), "SM2 private key cannot equal n-1");
}

namespace {

// Avoid the (unlikely) case of random generating an invalid key of n - 1
EC_Scalar generate_sm2_private_key(RandomNumberGenerator& rng, const EC_Group& group) {
   const auto one = EC_Scalar::one(group);

   for(;;) {
      // EC_Scalar::random never returns zero
      auto x = EC_Scalar::random(group, rng);
      BOTAN_ASSERT_NOMSG(x.is_nonzero());
      if((x + one).is_nonzero()) {
         return x;
      }
   }
}

}  // namespace

SM2_PrivateKey::SM2_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group) :
      SM2_PrivateKey(group, generate_sm2_private_key(rng, group)) {}

SM2_PrivateKey::SM2_PrivateKey(RandomNumberGenerator& rng, const EC_Group& group, const BigInt& x) :
      EC_PrivateKey(rng, group, x),
      m_da_inv((this->_private_key() + EC_Scalar::one(domain())).invert()),
      m_da_inv_legacy(m_da_inv.to_bigint()) {
   BOTAN_ARG_CHECK(m_da_inv.is_nonzero(), "SM2 private key cannot equal n-1");
}

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
std::vector<uint8_t> sm2_compute_za(HashFunction& hash,
                                    std::string_view user_id,
                                    const EC_Group& group,
                                    const EC_Point& pubkey) {
   auto apoint = EC_AffinePoint(group, pubkey);
   return sm2_compute_za(hash, user_id, group, apoint);
}
#endif

namespace {

std::vector<uint8_t> sm2_compute_za(HashFunction& hash,
                                    std::span<const uint8_t> user_id,
                                    const EC_Group& group,
                                    const EC_AffinePoint& pubkey) {
   if(user_id.size() >= 8192) {
      throw Invalid_Argument("SM2 user id too long to represent");
   }

   const uint16_t uid_len = static_cast<uint16_t>(8 * user_id.size());

   hash.update(get_byte<0>(uid_len));
   hash.update(get_byte<1>(uid_len));
   hash.update(user_id);

   const size_t p_bytes = group.get_p_bytes();

   hash.update(group.get_a().serialize(p_bytes));
   hash.update(group.get_b().serialize(p_bytes));
   hash.update(group.get_g_x().serialize(p_bytes));
   hash.update(group.get_g_y().serialize(p_bytes));
   hash.update(pubkey.xy_bytes());

   return hash.final<std::vector<uint8_t>>();
}

}  // namespace

std::vector<uint8_t> sm2_compute_za(HashFunction& hash,
                                    std::string_view user_id,
                                    const EC_Group& group,
                                    const EC_AffinePoint& pubkey) {
   return sm2_compute_za(hash, as_span_of_bytes(user_id), group, pubkey);
}

namespace {

// GM/T 0009-2012 specifies this as the default userid
// "1234567812345678";
std::vector<uint8_t> sm2_default_userid() {
   return {
      // clang-format off
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      // clang-format on
   };
}

// SM3 is the only hash specified for use with SM2, so it is the default
std::string sm2_hash_function(const PK_Signature_Options& options) {
   return options.hash_function().value_or("SM3");
}

/*
* The input to the signature equation: normally e = H(ZA || M), but if the
* caller provides the digest directly then no ZA is computed and the context
* is not used.
*/
class SM2_Signature_Input final {
   public:
      SM2_Signature_Input(const PK_Signature_Options& options, const EC_Group& group, const EC_AffinePoint& pubkey) :
            m_group(group) {
         if(options.using_externally_computed_prehash()) {
            if(auto prehash = externally_computed_prehash_name(options)) {
               m_prehash_name = *prehash;
               m_expected_digest_len = HashFunction::create_or_throw(*prehash)->output_length();
            }
         } else {
            auto context = options.context().value_or(sm2_default_userid());

            m_hash = HashFunction::create_or_throw(sm2_hash_function(options));
            // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
            m_za = sm2_compute_za(*m_hash, context, m_group, pubkey);
            m_hash->update(m_za);
         }
      }

      void update(std::span<const uint8_t> input) {
         if(m_hash) {
            m_hash->update(input);
         } else {
            m_digest.insert(m_digest.end(), input.begin(), input.end());
         }
      }

      EC_Scalar final_e() {
         if(m_hash) {
            auto e = EC_Scalar::from_bytes_mod_order(m_group, m_hash->final());
            // prepend ZA for next signature if any
            m_hash->update(m_za);
            return e;
         }

         secure_vector<uint8_t> digest;
         std::swap(digest, m_digest);

         if(m_expected_digest_len > 0 && digest.size() != m_expected_digest_len) {
            throw Invalid_Argument(fmt("SM2 was configured to use a {} byte {} prehash but was given {} bytes",
                                       m_expected_digest_len,
                                       m_prehash_name,
                                       digest.size()));
         }

         return EC_Scalar::from_bytes_mod_order(m_group, digest);
      }

      std::string hash_function() const {
         if(m_hash) {
            return m_hash->name();
         }
         return m_prehash_name.empty() ? "Raw" : m_prehash_name;
      }

   private:
      const EC_Group m_group;
      std::vector<uint8_t> m_za;
      std::unique_ptr<HashFunction> m_hash;
      secure_vector<uint8_t> m_digest;
      std::string m_prehash_name;
      size_t m_expected_digest_len = 0;
};

/**
* SM2 signature operation
*/
class SM2_Signature_Operation final : public PK_Ops::Signature {
   public:
      SM2_Signature_Operation(const SM2_PrivateKey& sm2, const PK_Signature_Options& options) :
            m_group(sm2.domain()),
            m_x(sm2._private_key()),
            m_da_inv(sm2._get_da_inv()),
            m_input(options, m_group, sm2._public_ec_point()) {}

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      void update(std::span<const uint8_t> input) override { m_input.update(input); }

      std::vector<uint8_t> sign(RandomNumberGenerator& rng) override;

      std::string hash_function() const override { return m_input.hash_function(); }

   private:
      const EC_Group m_group;
      const EC_Scalar m_x;
      const EC_Scalar m_da_inv;
      SM2_Signature_Input m_input;
};

std::vector<uint8_t> SM2_Signature_Operation::sign(RandomNumberGenerator& rng) {
   const auto e = m_input.final_e();

   const auto k = EC_Scalar::random(m_group, rng);

   const auto r = EC_Scalar::gk_x_mod_order(k, rng) + e;
   const auto s = (k - r * m_x) * m_da_inv;

   const auto rs = r + s;

   // With overwhelming probability, a bug rather than actual zero r/s
   if(r.is_zero() || s.is_zero() || rs.is_zero()) {
      throw Internal_Error("During SM2 signature generated zero r/s");
   }

   return EC_Scalar::serialize_pair(r, s);
}

/**
* SM2 verification operation
*/
class SM2_Verification_Operation final : public PK_Ops::Verification {
   public:
      SM2_Verification_Operation(const SM2_PublicKey& sm2, const PK_Signature_Options& options) :
            m_group(sm2.domain()),
            m_gy_mul(sm2._public_ec_point()),
            m_input(options, m_group, sm2._public_ec_point()) {}

      void update(std::span<const uint8_t> input) override { m_input.update(input); }

      bool is_valid_signature(std::span<const uint8_t> sig) override;

      std::string hash_function() const override { return m_input.hash_function(); }

   private:
      const EC_Group m_group;
      const EC_Group::Mul2Table m_gy_mul;
      SM2_Signature_Input m_input;
};

bool SM2_Verification_Operation::is_valid_signature(std::span<const uint8_t> sig) {
   const auto e = m_input.final_e();

   if(auto rs = EC_Scalar::deserialize_pair(m_group, sig)) {
      const auto& [r, s] = rs.value();

      if(r.is_nonzero() && s.is_nonzero()) {
         const auto t = r + s;
         if(t.is_nonzero()) {
            // Check if r - e = x_coord(g*s + y*t) % n
            return m_gy_mul.mul2_vartime_x_mod_order_eq(r - e, s, t);
         }
      }
   }
   return false;
}

}  // namespace

std::unique_ptr<Private_Key> SM2_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<SM2_PrivateKey>(rng, domain());
}

std::unique_ptr<PK_Ops::Verification> SM2_PublicKey::_create_verification_op(
   const PK_Signature_Options& options) const {
   if(!options.using_provider()) {
      return std::make_unique<SM2_Verification_Operation>(*this, options);
   }
   throw Provider_Not_Found(algo_name(), options.provider().value());
}

std::unique_ptr<PK_Ops::Signature> SM2_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                        const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);

   if(!options.using_provider()) {
      return std::make_unique<SM2_Signature_Operation>(*this, options);
   }
   throw Provider_Not_Found(algo_name(), options.provider().value());
}

}  // namespace Botan
