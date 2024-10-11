/**
* Implementation of
*   X-Wing: general-purpose hybrid post-quantum KEM
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/x_wing.h>

#include <botan/kyber.h>
#include <botan/x25519.h>
#include <botan/internal/hybrid_kem_ops.h>
#include <botan/internal/kex_to_kem_adapter.h>
#include <botan/internal/sha3.h>

namespace Botan {

namespace {

// TODO: We need ML_KEM IPD. Change the mode after ML_KEM is available.
const KyberMode X_WING_KYBER_MODE = KyberMode::Kyber768;
const size_t KYBER_PK_LEN = 1184;
const size_t KYBER_SK_LEN = 2400;

const size_t X25519_LEN = 32;
const size_t PK_LEN = KYBER_PK_LEN + X25519_LEN;
const size_t SK_LEN = KYBER_SK_LEN + 2 * X25519_LEN;

const size_t X_WING_SHARED_SECRET_LENGTH = 32;

// X-Wing draft Section 5.3: Combiner
void x_wing_secret_combiner(std::span<uint8_t> out_shared_secret,
                            const std::vector<secure_vector<uint8_t>>& shared_secrets,
                            const std::vector<std::vector<uint8_t>>& ciphertexts) {
   BOTAN_ARG_CHECK(out_shared_secret.size() == X_WING_SHARED_SECRET_LENGTH, "Invalid output buffer size");
   BOTAN_ARG_CHECK(shared_secrets.size() == 2 && ciphertexts.size() == 2,
                   "Mismatched number of shared secrets and ciphertexts");

   // 5.3 XWingLabel:   \./
   //                   /^\    (as concatenated bytes)
   const std::array<uint8_t, 6> x_wing_label = {'\\', '.', '/', '/', '^', '\\'};
   SHA_3 hash(8 * X_WING_SHARED_SECRET_LENGTH);
   hash.update(x_wing_label);
   hash.update(shared_secrets[0]);
   hash.update(shared_secrets[1]);
   hash.update(ciphertexts[0]);
   hash.update(ciphertexts[1]);
   return hash.final(out_shared_secret);
}

class X_Wing_Encryptor final : public KEM_Encryption_with_Combiner {
   public:
      X_Wing_Encryptor(const std::vector<std::unique_ptr<Public_Key>>& public_keys, std::string_view provider) :
            KEM_Encryption_with_Combiner(public_keys, provider) {}

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                  const std::vector<std::vector<uint8_t>>& ciphertexts,
                                  size_t /*desired_shared_key_len*/,
                                  std::span<const uint8_t> /*salt*/) override {
         x_wing_secret_combiner(out_shared_secret, shared_secrets, ciphertexts);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override { return X_WING_SHARED_SECRET_LENGTH; }
};

class X_Wing_Decryptor final : public KEM_Decryption_with_Combiner {
   public:
      X_Wing_Decryptor(const std::vector<std::unique_ptr<Private_Key>>& private_keys,
                       RandomNumberGenerator& rng,
                       const std::string_view provider) :
            KEM_Decryption_with_Combiner(private_keys, rng, provider) {}

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                  const std::vector<std::vector<uint8_t>>& ciphertexts,
                                  size_t /*desired_shared_key_len*/,
                                  std::span<const uint8_t> /*salt*/) override {
         x_wing_secret_combiner(out_shared_secret, shared_secrets, ciphertexts);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override { return X_WING_SHARED_SECRET_LENGTH; }
};

}  // namespace

X_Wing_PublicKey::X_Wing_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks) : Hybrid_PublicKey(std::move(pks)) {}

X_Wing_PublicKey::X_Wing_PublicKey(std::span<const uint8_t> pk_bytes) :
      X_Wing_PublicKey([&pk_bytes]() {
         BOTAN_ARG_CHECK(pk_bytes.size() == PK_LEN, "Invalid X-Wing public key size");
         BufferSlicer slicer(pk_bytes);
         std::vector<std::unique_ptr<Public_Key>> pks;
         pks.push_back(std::make_unique<Kyber_PublicKey>(slicer.take(KYBER_PK_LEN), X_WING_KYBER_MODE));
         pks.push_back(std::make_unique<KEX_to_KEM_Adapter_PublicKey>(
            std::make_unique<X25519_PublicKey>(slicer.take(X25519_LEN))));
         BOTAN_ASSERT_NOMSG(slicer.empty());
         return pks;
      }()) {}

std::string X_Wing_PublicKey::algo_name() const {
   return "X-Wing";
}

AlgorithmIdentifier X_Wing_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string(algo_name()), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

std::unique_ptr<Private_Key> X_Wing_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<X_Wing_PrivateKey>(rng);
}

std::unique_ptr<PK_Ops::KEM_Encryption> X_Wing_PublicKey::create_kem_encryption_op(std::string_view params,
                                                                                   std::string_view provider) const {
   if(params != "Raw" && !params.empty()) {
      throw Botan::Invalid_Argument("X-Wing encryption does not support KDFs");
   }
   return std::make_unique<X_Wing_Encryptor>(public_keys(), provider);
}

std::unique_ptr<X_Wing_PublicKey> X_Wing_PublicKey::from_public_keys(std::vector<std::unique_ptr<Public_Key>> pks) {
   return std::unique_ptr<X_Wing_PublicKey>(new X_Wing_PublicKey(std::move(pks)));
}

X_Wing_PrivateKey::X_Wing_PrivateKey(RandomNumberGenerator& rng) :
      X_Wing_PrivateKey([&rng]() {
         std::vector<std::unique_ptr<Private_Key>> sks;
         sks.push_back(std::make_unique<Kyber_PrivateKey>(rng, X_WING_KYBER_MODE));
         sks.push_back(std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::make_unique<X25519_PrivateKey>(rng)));

         return std::make_pair(extract_public_keys(sks), std::move(sks));
      }()) {}

X_Wing_PrivateKey::X_Wing_PrivateKey(std::span<const uint8_t> key_bytes) :
      X_Wing_PrivateKey([&key_bytes] {
         BOTAN_ARG_CHECK(key_bytes.size() == SK_LEN, "Invalid X-Wing private key size");
         std::vector<std::unique_ptr<Private_Key>> sks;
         BufferSlicer slicer(key_bytes);
         sks.push_back(std::make_unique<Kyber_PrivateKey>(slicer.take(KYBER_SK_LEN), X_WING_KYBER_MODE));
         sks.push_back(std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(
            std::make_unique<X25519_PrivateKey>(slicer.copy_as_secure_vector(X25519_LEN))));
         auto pk_x_bytes = slicer.take(X25519_LEN);
         BOTAN_ASSERT_NOMSG(slicer.empty());

         auto pks = extract_public_keys(sks);
         auto pk_x_bytes_from_sk = pks.at(1)->raw_public_key_bits();
         BOTAN_ARG_CHECK(std::equal(pk_x_bytes.begin(), pk_x_bytes.end(), pk_x_bytes_from_sk.begin()),
                         "X25519 public key in secret key does not match with secret value");

         return std::make_pair(std::move(pks), std::move(sks));
      }()) {}

std::unique_ptr<Public_Key> X_Wing_PrivateKey::public_key() const {
   return from_public_keys(extract_public_keys(private_keys()));
}

secure_vector<uint8_t> X_Wing_PrivateKey::raw_private_key_bits() const {
   // X-Wing RFC Draft section 5.2:
   //   sk, pk = concat(sk_M, sk_X, pk_X), concat(pk_M, pk_X)
   secure_vector<uint8_t> bits(SK_LEN);
   return concat(private_keys().at(0)->raw_private_key_bits(),
                 private_keys().at(1)->raw_private_key_bits(),
                 public_keys().at(1)->raw_public_key_bits());
   return bits;
}

bool X_Wing_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return Hybrid_PrivateKey::check_key(rng, strong);
}

std::unique_ptr<PK_Ops::KEM_Decryption> X_Wing_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                                    std::string_view params,
                                                                                    std::string_view provider) const {
   if(params != "Raw" && !params.empty()) {
      throw Botan::Invalid_Argument("X-Wing decryption does not support KDFs");
   }
   return std::make_unique<X_Wing_Decryptor>(private_keys(), rng, provider);
}

X_Wing_PrivateKey::X_Wing_PrivateKey(
   std::pair<std::vector<std::unique_ptr<Public_Key>>, std::vector<std::unique_ptr<Private_Key>>> key_pairs) :
      Hybrid_PublicKey(std::move(key_pairs.first)), Hybrid_PrivateKey(std::move(key_pairs.second)) {}

}  // namespace Botan
