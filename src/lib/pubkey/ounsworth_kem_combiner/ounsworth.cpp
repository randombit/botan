/**
* Implementation of the Ounsworth KEM combiner (draft-ounsworth-cfrg-kem-combiners-05)
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ounsworth.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/hybrid_kem_ops.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>

#include <algorithm>

namespace Botan {

namespace {

/// @returns the summed up size of a two dimensional vector
template <typename Alloc>
size_t flattened_size(const std::vector<std::vector<uint8_t, Alloc>>& a) {
   return reduce(a, size_t(0), [](size_t acc, const std::span<const uint8_t>& v) { return acc + v.size(); });
}

// 4.1. Bit length encoding (or right_encode of SP800-185 Section 2.3.1).
std::vector<uint8_t> rlen(std::span<const uint8_t> s) {
   // 1. Let x = len(s)
   const size_t x = s.size() * 8;
   // 1. Let n be the smallest positive integer for which 2^{8n} > x
   const size_t n = std::max(size_t(1), significant_bytes(x));
   // 2. Let x_1, x_2, ..., x_n be the base-256 encoding of x satisfying:
   //     x = sum 28(n-i)x i, for i = 1 to n
   // 3. Let O_i = uint8(x_i), for i = 1 to n
   const auto be_sz_encoding = store_be(x);
   BOTAN_ASSERT_NOMSG(be_sz_encoding.size() >= n);
   std::vector<uint8_t> o_i(be_sz_encoding.end() - n, be_sz_encoding.end());
   // 4. Let O_{n+1} = uint8(n)
   o_i.push_back(checked_cast_to_or_throw<uint8_t, Invalid_Argument>(n, "Too many input bytes"));
   // 5. rlen(s) = O_1 || O_2 || ... || O_n || O_{n+1}
   return o_i;
}

/// @returns the length encoding for each vector element
template <typename Alloc>
std::vector<std::vector<uint8_t>> rlen_vec(const std::vector<std::vector<uint8_t, Alloc>>& vec) {
   std::vector<std::vector<uint8_t>> result;
   std::transform(
      vec.begin(), vec.end(), std::back_inserter(result), [](std::span<const uint8_t> v) { return rlen(v); });
   return result;
}

/// Instantiates KDF of the specification
void ounsworth_secret_combiner(std::span<uint8_t> out_shared_secret,
                               const Ounsworth::Mode& mode,
                               const std::vector<secure_vector<uint8_t>>& shared_secrets,
                               const std::vector<std::vector<uint8_t>>& ciphertexts,
                               std::span<const uint8_t> fixed_info,
                               std::span<const uint8_t> big_k) {
   BOTAN_UNUSED(out_shared_secret, mode, shared_secrets, ciphertexts, fixed_info);
   BOTAN_ASSERT_NOMSG(shared_secrets.size() == ciphertexts.size());
   BOTAN_ASSERT_NOMSG(big_k.empty() || mode.is_mac_based_kdf());

   const auto ss_len_encodings = rlen_vec(shared_secrets);
   const auto ct_len_encodings = rlen_vec(ciphertexts);

   const size_t kdf_input_buffer_size = flattened_size(ciphertexts) + flattened_size(ct_len_encodings) +
                                        flattened_size(shared_secrets) + flattened_size(ss_len_encodings);

   secure_vector<uint8_t> kdf_input_buffer(kdf_input_buffer_size);
   BufferStuffer kdf_stuffer(kdf_input_buffer);

   // ct_1 || rlen(ct_1) || ss_1 || rlen(ss_1) || ct_2 || ...
   for(size_t i = 0; i < shared_secrets.size(); ++i) {
      kdf_stuffer.append(ciphertexts.at(i));
      kdf_stuffer.append(ct_len_encodings.at(i));
      kdf_stuffer.append(shared_secrets.at(i));
      kdf_stuffer.append(ss_len_encodings.at(i));
   }
   BOTAN_ASSERT_NOMSG(kdf_stuffer.full());

   mode.kdf_instance()->derive_key(out_shared_secret, kdf_input_buffer, big_k, fixed_info);
}

std::vector<uint8_t> get_mac_big_k(const Ounsworth::Mode& mode, std::string_view params) {
   BOTAN_ARG_CHECK(params.empty() || mode.is_mac_based_kdf(),
                   "Parameters for Ounsworth KEM combiner with SHA3 must be empty.");

   if(params.empty()) {
      // Use default_salt of SP800-56C2, Section 4.1, Implementation-Dependent Parameters 3.
      switch(mode.kdf_mode()) {
         // If H(x) = KMAC128 [...] the default_salt shall be an all-zero string of 164 bytes.
         case Ounsworth::Kdf_Type::KMAC128:
            return std::vector<uint8_t>(164, 0);
         // If H(x) = KMAC256 [...] the default_salt shall be an all-zero string of 132 bytes.
         case Ounsworth::Kdf_Type::KMAC256:
            return std::vector<uint8_t>(132, 0);
         // Hash based KDFs do not use a K.
         case Ounsworth::Kdf_Type::SHA3_256:
         case Ounsworth::Kdf_Type::SHA3_512:
            return {};
      }
      BOTAN_ASSERT_UNREACHABLE();
   } else {
      // By default K is the bytes of the input string.
      return {params.begin(), params.end()};
   }
}

/**
 * The Ounsworth combiner supports two domain separation mechanisms:
 *
 * 1. The required fixed_info parameter. In Botan it is represented as the salt
 *    parameter. This is NOT the salt of the underlying SP800-56C2 One-Step KDF.
 *
 * 2. Optional and only for KMAC based constructions: The context-specific
 *    string K, which is the key of the MAC. This string is passed via the
 *    params parameter in the create_kem_en/decryption_op. If it is empty,
 *    the default value is used as defined in SP800-56C2, Section 4.1,
 *    Implementation-Dependent Parameters 3. (named "default_salt").
 */
class Ounsworth_Encryptor final : public KEM_Encryption_with_Combiner {
   public:
      Ounsworth_Encryptor(const Ounsworth_PublicKey& public_key,
                          std::string_view mac_big_k,
                          std::string_view provider) :
            KEM_Encryption_with_Combiner(public_key.public_keys(), provider),
            m_mac_big_k(get_mac_big_k(public_key.mode(), mac_big_k)),
            m_mode(public_key.mode()) {}

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                  const std::vector<std::vector<uint8_t>>& ciphertexts,
                                  size_t /*desired_shared_key_len*/,
                                  std::span<const uint8_t> fixed_info) override {
         ounsworth_secret_combiner(out_shared_secret, m_mode, shared_secrets, ciphertexts, fixed_info, m_mac_big_k);
      }

      // The ciphertexts are concatenated without salt.
      void combine_ciphertexts(std::span<uint8_t> out_ciphertext,
                               const std::vector<std::vector<uint8_t>>& ciphertexts,
                               std::span<const uint8_t> /*salt*/) override {
         KEM_Encryption_with_Combiner::combine_ciphertexts(out_ciphertext, ciphertexts, {});
      }

      size_t shared_key_length(size_t desired_shared_key_len) const override { return desired_shared_key_len; }

   private:
      std::vector<uint8_t> m_mac_big_k;
      Ounsworth::Mode m_mode;
};

class Ounsworth_Decryptor final : public KEM_Decryption_with_Combiner {
   public:
      Ounsworth_Decryptor(const Ounsworth_PrivateKey& private_key,
                          RandomNumberGenerator& rng,
                          const std::string_view mac_big_k,
                          const std::string_view provider) :
            KEM_Decryption_with_Combiner(private_key.private_keys(), rng, provider),
            m_mac_big_k(get_mac_big_k(private_key.mode(), mac_big_k)),
            m_mode(private_key.mode()) {}

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                  const std::vector<std::vector<uint8_t>>& ciphertexts,
                                  size_t /*desired_shared_key_len*/,
                                  std::span<const uint8_t> salt) override {
         ounsworth_secret_combiner(out_shared_secret, m_mode, shared_secrets, ciphertexts, salt, m_mac_big_k);
      }

      size_t shared_key_length(size_t desired_shared_key_len) const override { return desired_shared_key_len; }

   private:
      std::vector<uint8_t> m_mac_big_k;
      Ounsworth::Mode m_mode;
};

}  // namespace

Ounsworth_PublicKey::Ounsworth_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks, const Ounsworth::Mode& mode) :
      Hybrid_PublicKey(std::move(pks)), m_mode(mode) {}

Ounsworth_PublicKey::Ounsworth_PublicKey(std::span<const uint8_t> pk_bytes, const Ounsworth::Mode& mode) :
      Ounsworth_PublicKey(
         [&]() {
            BOTAN_ARG_CHECK(pk_bytes.size() == mode.pk_length(), "Invalid Ounsworth KEM combiner public key size");
            BufferSlicer slicer(pk_bytes);
            std::vector<std::unique_ptr<Public_Key>> pks;
            std::transform(mode.sub_algos().begin(),
                           mode.sub_algos().end(),
                           std::back_inserter(pks),
                           [&](const Ounsworth::Sub_Algo& sub_algo) {
                              return sub_algo.load_public_key(slicer.take(sub_algo.raw_pk_length()));
                           });
            BOTAN_ASSERT_NOMSG(slicer.empty());
            return pks;
         }(),
         mode) {}

Ounsworth_PublicKey::Ounsworth_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk_bytes) :
      Ounsworth_PublicKey(pk_bytes, Ounsworth::Mode(alg_id)) {}

std::string Ounsworth_PublicKey::algo_name() const {
   return Ounsworth::Mode::algorithm_name();
}

AlgorithmIdentifier Ounsworth_PublicKey::algorithm_identifier() const {
   return m_mode.algorithm_identifier();
}

std::unique_ptr<Private_Key> Ounsworth_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Ounsworth_PrivateKey>(rng, m_mode);
}

std::unique_ptr<PK_Ops::KEM_Encryption> Ounsworth_PublicKey::create_kem_encryption_op(std::string_view mac_big_k,
                                                                                      std::string_view provider) const {
   return std::make_unique<Ounsworth_Encryptor>(*this, mac_big_k, provider);
}

std::unique_ptr<Ounsworth_PublicKey> Ounsworth_PublicKey::from_public_keys(std::vector<std::unique_ptr<Public_Key>> pks,
                                                                           const Ounsworth::Mode& mode) {
   return std::unique_ptr<Ounsworth_PublicKey>(new Ounsworth_PublicKey(std::move(pks), mode));
}

Ounsworth_PrivateKey::Ounsworth_PrivateKey(RandomNumberGenerator& rng, const Ounsworth::Mode& mode) :
      Ounsworth_PrivateKey(
         [&]() {
            std::vector<std::unique_ptr<Private_Key>> sks;
            std::transform(mode.sub_algos().begin(),
                           mode.sub_algos().end(),
                           std::back_inserter(sks),
                           [&](const Ounsworth::Sub_Algo& sub_algo) { return sub_algo.create_private_key(rng); });

            std::vector<std::unique_ptr<Public_Key>> pks = extract_public_keys(sks);
            return std::make_pair(std::move(pks), std::move(sks));
         }(),
         mode) {}

Ounsworth_PrivateKey::Ounsworth_PrivateKey(std::span<const uint8_t> key_bytes, const Ounsworth::Mode& mode) :
      Ounsworth_PrivateKey(
         [&] {
            BOTAN_ARG_CHECK(key_bytes.size() == mode.sk_length(), "Invalid Ounsworth KEM combiner private key size");
            std::vector<std::unique_ptr<Private_Key>> sks;
            BufferSlicer slicer(key_bytes);
            std::transform(mode.sub_algos().begin(),
                           mode.sub_algos().end(),
                           std::back_inserter(sks),
                           [&](const Ounsworth::Sub_Algo& sub_algo) {
                              return sub_algo.load_private_key(slicer.take(sub_algo.raw_sk_length()));
                           });
            BOTAN_ASSERT_NOMSG(slicer.empty());

            std::vector<std::unique_ptr<Public_Key>> pks = extract_public_keys(sks);
            return std::make_pair(std::move(pks), std::move(sks));
         }(),
         mode) {}

Ounsworth_PrivateKey::Ounsworth_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bytes) :
      Ounsworth_PrivateKey(key_bytes, Ounsworth::Mode(alg_id)) {}

std::unique_ptr<Public_Key> Ounsworth_PrivateKey::public_key() const {
   return from_public_keys(extract_public_keys(private_keys()), mode());
}

secure_vector<uint8_t> Ounsworth_PrivateKey::raw_private_key_bits() const {
   secure_vector<uint8_t> sk_bytes;
   sk_bytes.reserve(mode().sk_length());
   for(const auto& sk : private_keys()) {
      const auto sk_bytes_part = sk->raw_private_key_bits();
      sk_bytes.insert(sk_bytes.end(), sk_bytes_part.begin(), sk_bytes_part.end());
   }
   BOTAN_ASSERT(sk_bytes.size() == mode().sk_length(), "Some private key length does not match the expected length.");
   return sk_bytes;
}

bool Ounsworth_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return Hybrid_PrivateKey::check_key(rng, strong);
}

std::unique_ptr<PK_Ops::KEM_Decryption> Ounsworth_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view mac_big_k, std::string_view provider) const {
   return std::make_unique<Ounsworth_Decryptor>(*this, rng, mac_big_k, provider);
}

Ounsworth_PrivateKey::Ounsworth_PrivateKey(
   std::pair<std::vector<std::unique_ptr<Public_Key>>, std::vector<std::unique_ptr<Private_Key>>> key_pairs,
   const Ounsworth::Mode& mode) :
      Hybrid_PublicKey(std::move(key_pairs.first)),
      Ounsworth_PublicKey(mode),
      Hybrid_PrivateKey(std::move(key_pairs.second)) {}

}  // namespace Botan
