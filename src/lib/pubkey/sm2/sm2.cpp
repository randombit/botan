/*
* SM2 Signatures
* (C) 2017,2018 Ribose Inc
* (C) 2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm2.h>

#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/numthry.h>
#include <botan/internal/keypair.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

std::string SM2_PublicKey::algo_name() const {
   return "SM2";
}

std::unique_ptr<Public_Key> SM2_PrivateKey::public_key() const {
   return std::make_unique<SM2_Signature_PublicKey>(domain(), public_point());
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
      EC_PrivateKey(alg_id, key_bits),
      m_da_inv((this->_private_key() + EC_Scalar::one(domain())).invert()),
      m_da_inv_legacy(m_da_inv.to_bigint()) {}

SM2_PrivateKey::SM2_PrivateKey(RandomNumberGenerator& rng, EC_Group group, const BigInt& x) :
      EC_PrivateKey(rng, std::move(group), x),
      m_da_inv((this->_private_key() + EC_Scalar::one(domain())).invert()),
      m_da_inv_legacy(m_da_inv.to_bigint()) {}

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

namespace {

// GM/T 0009-2012 specifies this as the default userid
// "1234567812345678";
const std::vector<uint8_t> sm2_default_userid = {
   // clang-format off
   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
   // clang-format on
};

}  // namespace

/**
* SM2 signature operation
*/
class SM2_Signature_Operation final : public PK_Ops::Signature {
   public:
      SM2_Signature_Operation(const SM2_PrivateKey& sm2, PK_Signature_Options& options) :
            m_group(sm2.domain()), m_x(sm2._private_key()), m_da_inv(sm2._get_da_inv()) {
         const auto hash = options.hash_function();
         if(hash == "Raw") {
            // m_hash is null, m_za is empty
         } else {
            auto context = options.context().value_or(sm2_default_userid);

            m_hash = HashFunction::create_or_throw(hash);
            // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
            m_za = sm2_compute_za(*m_hash, context, m_group, sm2._public_key());
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
      std::vector<BigInt> m_ws;
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

   const auto r = EC_Scalar::gk_x_mod_order(k, rng, m_ws) + e;
   const auto s = (k - r * m_x) * m_da_inv;

   return EC_Scalar::serialize_pair(r, s);
}

/**
* SM2 verification operation
*/
class SM2_Verification_Operation final : public PK_Ops::Verification {
   public:
      SM2_Verification_Operation(const SM2_PublicKey& sm2, PK_Signature_Options& options) :
            m_group(sm2.domain()), m_gy_mul(sm2._public_key()) {
         const auto hash = options.hash_function();
         if(hash == "Raw") {
            // m_hash is null, m_za is empty
         } else {
            auto context = options.context().value_or(sm2_default_userid);

            m_hash = HashFunction::create_or_throw(hash);
            // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
            m_za = sm2_compute_za(*m_hash, context, m_group, sm2._public_key());
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

}  // namespace

std::unique_ptr<Private_Key> SM2_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<SM2_PrivateKey>(rng, domain());
}

std::vector<uint8_t> sm2_compute_za(HashFunction& hash,
                                    std::string_view ident,
                                    const EC_Group& group,
                                    const EC_Point& point) {
   auto apoint = EC_AffinePoint(group, point);
   const auto ident_bytes = std::span{cast_char_ptr_to_uint8(ident.data()), ident.size()};
   return sm2_compute_za(hash, ident_bytes, group, apoint);
}

std::unique_ptr<PK_Ops::Verification> SM2_PublicKey::_create_verification_op(PK_Signature_Options& options) const {
   options.exclude_provider_for_algorithm(algo_name());
   return std::make_unique<SM2_Verification_Operation>(*this, options);
}

std::unique_ptr<PK_Ops::Signature> SM2_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                        PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);
   options.exclude_provider_for_algorithm(algo_name());
   return std::make_unique<SM2_Signature_Operation>(*this, options);
}

}  // namespace Botan
