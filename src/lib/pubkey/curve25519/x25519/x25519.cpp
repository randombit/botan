/*
* X25519
* (C) 2014,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x25519.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/pk_options_impl.h>
#include <botan/internal/x25519_internal.h>
#include <array>

namespace Botan {

class X25519_PublicKey_Data final {
   public:
      explicit X25519_PublicKey_Data(std::vector<uint8_t> key) : m_key(std::move(key)) {}

      const std::vector<uint8_t>& key() const { return m_key; }

   private:
      std::vector<uint8_t> m_key;
};

class X25519_PrivateKey_Data final {
   public:
      explicit X25519_PrivateKey_Data(secure_vector<uint8_t> key) : m_key(std::move(key)) {}

      const secure_vector<uint8_t>& key() const { return m_key; }

   private:
      secure_vector<uint8_t> m_key;
};

const secure_vector<uint8_t>& X25519_PrivateKey::get_x() const {
   return m_private->key();
}

secure_vector<uint8_t> X25519_PrivateKey::raw_private_key_bits() const {
   return m_private->key();
}

namespace {

void size_check(size_t size, const char* thing) {
   if(size != 32) {
      throw Decoding_Error(fmt("Invalid size {} for X25519 {}", size, thing));
   }
}

// X25519 agreement, shared by agree() and the PK_Key_Agreement operation
secure_vector<uint8_t> x25519_agree(const secure_vector<uint8_t>& secret, const uint8_t pubval[32]) {
   BOTAN_ASSERT_NOMSG(secret.size() == 32);
   secure_vector<uint8_t> shared_key(32);
   x25519_scalarmult(std::span<uint8_t, 32>(shared_key.data(), 32),
                     std::span<const uint8_t, 32>(secret.data(), 32),
                     std::span<const uint8_t, 32>(pubval, 32));

   // RFC 7748 Section 6.1
   //    Both [parties] MAY check, without leaking extra information about
   //    the value of K, whether K is the all-zero value and abort if so.
   //
   // TODO: once the generic Key Agreement operation creation is equipped
   //       with a more flexible parameterization, this check could be
   //       made optional.
   //       For instance: `sk->agree().with_optional_sanity_checks(true)`.
   //       See also:     https://github.com/randombit/botan/pull/4318
   if(CT::all_zeros(shared_key.data(), shared_key.size()).as_bool()) {
      throw Invalid_Argument("X25519 public point appears to be of low order");
   }

   return shared_key;
}

// Given a 32-byte secret key compute the public value and build the immutable
// public and private key data objects.
void load_x25519_keypair(secure_vector<uint8_t> secret,
                         std::shared_ptr<const X25519_PublicKey_Data>& pk_out,
                         std::shared_ptr<const X25519_PrivateKey_Data>& sk_out) {
   BOTAN_ASSERT_NOMSG(secret.size() == 32);
   std::vector<uint8_t> pub(32);
   x25519_basepoint(std::span<uint8_t, 32>(pub.data(), 32), std::span<const uint8_t, 32>(secret.data(), 32));
   pk_out = std::make_shared<const X25519_PublicKey_Data>(std::move(pub));
   sk_out = std::make_shared<const X25519_PrivateKey_Data>(std::move(secret));
}

}  // namespace

AlgorithmIdentifier X25519_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

bool X25519_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   /*
   * Every clamped scalar is a multiple of the cofactor, so multiplying by one
   * sends exactly the points of low order to the identity (all zero output).
   * Nothing else can be checked for a Montgomery u-coordinate.
   */
   const std::array<uint8_t, 32> scalar{};  // clamped to 2^254 by x25519_scalarmult
   std::array<uint8_t, 32> out{};
   x25519_scalarmult(out, scalar, std::span<const uint8_t, 32>(m_public->key().data(), 32));
   return !CT::all_zeros(out.data(), out.size()).as_bool();
}

X25519_PublicKey::X25519_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      X25519_PublicKey(key_bits) {
   // RFC 8410 Section 3: "the parameters MUST be absent".
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for X25519 public key");
   }
}

X25519_PublicKey::X25519_PublicKey(std::span<const uint8_t> pub) {
   size_check(pub.size(), "public key");
   m_public = std::make_shared<const X25519_PublicKey_Data>(std::vector<uint8_t>(pub.begin(), pub.end()));
}

std::vector<uint8_t> X25519_PublicKey::raw_public_key_bits() const {
   return m_public->key();
}

std::vector<uint8_t> X25519_PublicKey::public_key_bits() const {
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> X25519_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<X25519_PrivateKey>(rng);
}

X25519_PrivateKey::X25519_PrivateKey(std::span<const uint8_t> secret_key) {
   if(secret_key.size() != 32) {
      throw Decoding_Error("Invalid size for X25519 private key");
   }

   load_x25519_keypair(secure_vector<uint8_t>(secret_key.begin(), secret_key.end()), m_public, m_private);
}

X25519_PrivateKey::X25519_PrivateKey(RandomNumberGenerator& rng) {
   load_x25519_keypair(rng.random_vec(32), m_public, m_private);
}

X25519_PrivateKey::X25519_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   // RFC 8410 Section 3: "the parameters MUST be absent".
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for X25519 private key");
   }

   secure_vector<uint8_t> secret_key;
   BER_Decoder(key_bits, BER_Decoder::Limits::DER()).decode(secret_key, ASN1_Type::OctetString).verify_end();

   size_check(secret_key.size(), "private key");
   load_x25519_keypair(std::move(secret_key), m_public, m_private);
}

std::unique_ptr<Public_Key> X25519_PrivateKey::public_key() const {
   return std::make_unique<X25519_PublicKey>(public_value());
}

secure_vector<uint8_t> X25519_PrivateKey::private_key_bits() const {
   return DER_Encoder().encode(m_private->key(), ASN1_Type::OctetString).get_contents();
}

bool X25519_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   std::vector<uint8_t> public_point(32);
   x25519_basepoint(std::span<uint8_t, 32>(public_point.data(), 32),
                    std::span<const uint8_t, 32>(m_private->key().data(), 32));
   return public_point == m_public->key();
}

secure_vector<uint8_t> X25519_PrivateKey::agree(const uint8_t w[], size_t w_len) const {
   size_check(w_len, "public value");
   return x25519_agree(m_private->key(), w);
}

namespace {

/**
* X25519 operation
*/
class X25519_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF {
   public:
      X25519_KA_Operation(std::shared_ptr<const X25519_PrivateKey_Data> key,
                          const PK_Key_Agreement_Options_Reader& options) :
            PK_Ops::Key_Agreement_with_KDF(options), m_key(std::move(key)) {}

      size_t agreed_value_size() const override { return 32; }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
         size_check(w_len, "public value");
         return x25519_agree(m_key->key(), w);
      }

   private:
      std::shared_ptr<const X25519_PrivateKey_Data> m_key;
};

}  // namespace

std::unique_ptr<PK_Ops::Key_Agreement> X25519_PrivateKey::_create_key_agreement_op(
   RandomNumberGenerator& /*rng*/, const PK_Key_Agreement_Options_Reader& options) const {
   require_software_provider(options, algo_name());

   return std::make_unique<X25519_KA_Operation>(m_private, options);
}

// Deprecated free functions, not used by the library itself

void curve25519_donna(uint8_t mypublic[32], const uint8_t secret[32], const uint8_t basepoint[32]) {
   x25519_scalarmult(std::span<uint8_t, 32>(mypublic, 32),
                     std::span<const uint8_t, 32>(secret, 32),
                     std::span<const uint8_t, 32>(basepoint, 32));
}

void curve25519_basepoint(uint8_t mypublic[32], const uint8_t secret[32]) {
   x25519_basepoint(std::span<uint8_t, 32>(mypublic, 32), std::span<const uint8_t, 32>(secret, 32));
}

}  // namespace Botan
