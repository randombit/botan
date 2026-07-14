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
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

std::string SM2_PublicKey::algo_name() const {
   return "SM2";
}

namespace {

const AlgorithmIdentifier& assert_sm2_algorithm_identifier(const AlgorithmIdentifier& alg_id) {
   if(alg_id.oid() != OID::from_string("SM2") && alg_id.oid() != OID::from_string("SM2_Enc")) {
      throw Decoding_Error(fmt("Unexpected AlgorithmIdentifier OID {} in association with SM2 key", alg_id.oid()));
   }

   return alg_id;
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

std::vector<uint8_t> sm2_compute_za(HashFunction& hash,
                                    std::string_view user_id,
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

namespace {

/**
* SM2 signature operation
*/
class SM2_Signature_Operation final : public PK_Ops::Signature {
   public:
      SM2_Signature_Operation(const SM2_PrivateKey& sm2, std::string_view ident, std::string_view hash) :
            m_group(sm2.domain()), m_x(sm2._private_key()), m_da_inv(sm2._get_da_inv()) {
         if(hash == "Raw") {
            // m_hash is null, m_za is empty
         } else {
            m_hash = HashFunction::create_or_throw(hash);
            // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
            m_za = sm2_compute_za(*m_hash, ident, m_group, sm2._public_ec_point());
            m_hash->update(m_za);
         }
      }

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      void update(std::span<const uint8_t> input) override {
         if(m_hash) {
            m_hash->update(input);
         } else {
            m_digest.insert(m_digest.end(), input.begin(), input.end());
         }
      }

      std::vector<uint8_t> sign(RandomNumberGenerator& rng) override;

      std::string hash_function() const override { return m_hash ? m_hash->name() : "Raw"; }

   private:
      const EC_Group m_group;
      const EC_Scalar m_x;
      const EC_Scalar m_da_inv;

      std::vector<uint8_t> m_za;
      secure_vector<uint8_t> m_digest;
      std::unique_ptr<HashFunction> m_hash;
};

std::vector<uint8_t> SM2_Signature_Operation::sign(RandomNumberGenerator& rng) {
   const auto e = [&]() {
      if(m_hash) {
         auto ie = EC_Scalar::from_bytes_mod_order(m_group, m_hash->final());
         // prepend ZA for next signature if any
         m_hash->update(m_za);
         return ie;
      } else {
         auto ie = EC_Scalar::from_bytes_mod_order(m_group, m_digest);
         m_digest.clear();
         return ie;
      }
   }();

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
      SM2_Verification_Operation(const SM2_PublicKey& sm2, std::string_view ident, std::string_view hash) :
            m_group(sm2.domain()), m_gy_mul(sm2._public_ec_point()) {
         if(hash == "Raw") {
            // m_hash is null, m_za is empty
         } else {
            m_hash = HashFunction::create_or_throw(hash);
            // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
            m_za = sm2_compute_za(*m_hash, ident, m_group, sm2._public_ec_point());
            m_hash->update(m_za);
         }
      }

      void update(std::span<const uint8_t> input) override {
         if(m_hash) {
            m_hash->update(input);
         } else {
            m_digest.insert(m_digest.end(), input.begin(), input.end());
         }
      }

      bool is_valid_signature(std::span<const uint8_t> sig) override;

      std::string hash_function() const override { return m_hash ? m_hash->name() : "Raw"; }

   private:
      const EC_Group m_group;
      const EC_Group::Mul2Table m_gy_mul;
      secure_vector<uint8_t> m_digest;
      std::vector<uint8_t> m_za;
      std::unique_ptr<HashFunction> m_hash;
};

bool SM2_Verification_Operation::is_valid_signature(std::span<const uint8_t> sig) {
   const auto e = [&]() {
      if(m_hash) {
         auto ie = EC_Scalar::from_bytes_mod_order(m_group, m_hash->final());
         // prepend ZA for next signature if any
         m_hash->update(m_za);
         return ie;
      } else {
         auto ie = EC_Scalar::from_bytes_mod_order(m_group, m_digest);
         m_digest.clear();
         return ie;
      }
   }();

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

std::pair<std::string, std::string> parse_sm2_param_string(std::string_view params) {
   const std::string default_hash = "SM3";

   /*
   * SM2 parameters have the following possible formats:
   * Ident [since 2.2.0]
   * Ident,Hash [since 2.3.0]
   *
   * Historically a completely empty parameter string was treated as
   * if the identity was empty. This probably should have instead been
   * treated as if it was the "default userid" ("1234567812345678") but
   * there was a bug and it wasn't.
   *
   * TODO(Botan4) evaluate if this should be changed
   */
   if(params.empty()) {
      return std::make_pair(std::string(), default_hash);
   }

   auto comma = params.find(',');
   if(comma == std::string::npos) {
      return std::make_pair(std::string(params), default_hash);
   } else {
      const auto userid = params.substr(0, comma);
      const auto hash = params.substr(comma + 1, std::string::npos);
      return std::make_pair(std::string(userid), std::string(hash));
   }
}

}  // namespace

std::unique_ptr<Private_Key> SM2_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<SM2_PrivateKey>(rng, domain());
}

std::unique_ptr<PK_Ops::Verification> SM2_PublicKey::create_verification_op(std::string_view params,
                                                                            std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      const auto [userid, hash] = parse_sm2_param_string(params);
      return std::make_unique<SM2_Verification_Operation>(*this, userid, hash);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> SM2_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                       std::string_view params,
                                                                       std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      const auto [userid, hash] = parse_sm2_param_string(params);
      return std::make_unique<SM2_Signature_Operation>(*this, userid, hash);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
