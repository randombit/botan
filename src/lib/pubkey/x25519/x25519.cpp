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

namespace Botan {

void curve25519_basepoint(uint8_t mypublic[32], const uint8_t secret[32]) {
   const uint8_t basepoint[32] = {9};
   curve25519_donna(mypublic, secret, basepoint);
}

namespace {

void size_check(size_t size, const char* thing) {
   if(size != 32) {
      throw Decoding_Error(fmt("Invalid size {} for X25519 {}", size, thing));
   }
}

secure_vector<uint8_t> curve25519(const secure_vector<uint8_t>& secret, const uint8_t pubval[32]) {
   secure_vector<uint8_t> out(32);
   curve25519_donna(out.data(), secret.data(), pubval);
   return out;
}

}  // namespace

AlgorithmIdentifier X25519_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

bool X25519_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   return true;  // no tests possible?
}

X25519_PublicKey::X25519_PublicKey(const AlgorithmIdentifier& /*unused*/, std::span<const uint8_t> key_bits) :
      X25519_PublicKey(key_bits) {}

X25519_PublicKey::X25519_PublicKey(std::span<const uint8_t> pub) {
   m_public.assign(pub.begin(), pub.end());

   size_check(m_public.size(), "public key");
}

std::vector<uint8_t> X25519_PublicKey::raw_public_key_bits() const {
   return m_public;
}

std::vector<uint8_t> X25519_PublicKey::public_key_bits() const {
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> X25519_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<X25519_PrivateKey>(rng);
}

X25519_PrivateKey::X25519_PrivateKey(const secure_vector<uint8_t>& secret_key) {
   if(secret_key.size() != 32) {
      throw Decoding_Error("Invalid size for X25519 private key");
   }

   m_public.resize(32);
   m_private = secret_key;
   curve25519_basepoint(m_public.data(), m_private.data());
}

X25519_PrivateKey::X25519_PrivateKey(RandomNumberGenerator& rng) {
   m_private = rng.random_vec(32);
   m_public.resize(32);
   curve25519_basepoint(m_public.data(), m_private.data());
}

X25519_PrivateKey::X25519_PrivateKey(const AlgorithmIdentifier& /*unused*/, std::span<const uint8_t> key_bits) {
   BER_Decoder(key_bits).decode(m_private, ASN1_Type::OctetString).discard_remaining();

   size_check(m_private.size(), "private key");
   m_public.resize(32);
   curve25519_basepoint(m_public.data(), m_private.data());
}

std::unique_ptr<Public_Key> X25519_PrivateKey::public_key() const {
   return std::make_unique<X25519_PublicKey>(public_value());
}

secure_vector<uint8_t> X25519_PrivateKey::private_key_bits() const {
   return DER_Encoder().encode(m_private, ASN1_Type::OctetString).get_contents();
}

bool X25519_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   std::vector<uint8_t> public_point(32);
   curve25519_basepoint(public_point.data(), m_private.data());
   return public_point == m_public;
}

secure_vector<uint8_t> X25519_PrivateKey::agree(const uint8_t w[], size_t w_len) const {
   size_check(w_len, "public value");
   return curve25519(m_private, w);
}

namespace {

/**
* X25519 operation
*/
class X25519_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF {
   public:
      X25519_KA_Operation(const X25519_PrivateKey& key, std::string_view kdf) :
            PK_Ops::Key_Agreement_with_KDF(kdf), m_key(key) {}

      size_t agreed_value_size() const override { return 32; }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
         auto shared_key = m_key.agree(w, w_len);

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

   private:
      const X25519_PrivateKey& m_key;
};

}  // namespace

std::unique_ptr<PK_Ops::Key_Agreement> X25519_PrivateKey::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
                                                                                  std::string_view params,
                                                                                  std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<X25519_KA_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
