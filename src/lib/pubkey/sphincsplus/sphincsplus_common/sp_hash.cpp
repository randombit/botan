/*
 * SLH-DSA Hash Function Interface
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/sp_hash.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/sp_parameters.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/hash_engine.h>
#include <memory>

#if defined(BOTAN_HAS_SPHINCS_PLUS_SHAKE_BASE)
   #include <botan/internal/sp_hash_shake.h>
#endif

#if defined(BOTAN_HAS_SPHINCS_PLUS_SHA2_BASE)
   #include <botan/internal/sp_hash_sha2.h>
#endif

namespace Botan {

Sphincs_Hash_Functions::Sphincs_Hash_Functions(const Sphincs_Parameters& sphincs_params,
                                               const SphincsPublicSeed& pub_seed) :
      m_sphincs_params(sphincs_params), m_pub_seed(pub_seed) {}

void Sphincs_Hash_Functions::T_batch(std::span<std::span<uint8_t>> outputs,
                                     std::span<const Sphincs_Address> addresses,
                                     std::span<std::span<const uint8_t>> inputs) {
   BOTAN_ASSERT_NOMSG(outputs.size() == addresses.size() && addresses.size() == inputs.size());

   if(addresses.empty()) {
      return;
   }

   auto& engine = tweak_hash_engine(inputs[0].size());

   const size_t adrs_len = address_encoding_len();
   m_adrs_buf.resize(addresses.size() * adrs_len);
   m_adrs_spans.resize(addresses.size());

   for(size_t i = 0; i != addresses.size(); ++i) {
      const auto adrs = std::span(m_adrs_buf).subspan(i * adrs_len, adrs_len);
      encode_address(adrs, addresses[i]);
      m_adrs_spans[i] = adrs;
   }

   engine.batch_hash(outputs, m_adrs_spans, inputs);
}

void Sphincs_Hash_Functions::PRF_batch(std::span<std::span<uint8_t>> outputs,
                                       const SphincsSecretSeed& sk_seed,
                                       std::span<const Sphincs_Address> addresses) {
   m_prf_inputs.assign(addresses.size(), std::span<const uint8_t>(sk_seed.get()));
   T_batch(outputs, addresses, m_prf_inputs);
}

std::unique_ptr<Sphincs_Hash_Functions> Sphincs_Hash_Functions::create(const Sphincs_Parameters& sphincs_params,
                                                                       const SphincsPublicSeed& pub_seed) {
   switch(sphincs_params.hash_type()) {
      case Sphincs_Hash_Type::Sha256:
#if defined(BOTAN_HAS_SPHINCS_PLUS_SHA2_BASE)
         return std::make_unique<Sphincs_Hash_Functions_Sha2>(sphincs_params, pub_seed);
#else
         throw Not_Implemented("SLH-DSA (or SPHINCS+) with SHA-256 is not available in this build");
#endif

      case Sphincs_Hash_Type::Shake256:
#if defined(BOTAN_HAS_SPHINCS_PLUS_SHAKE_BASE)
         return std::make_unique<Sphincs_Hash_Functions_Shake>(sphincs_params, pub_seed);
#else
         throw Not_Implemented("SLH-DSA (or SPHINCS+) with SHAKE is not available in this build");
#endif

      case Sphincs_Hash_Type::Haraka:
         throw Not_Implemented("Haraka is not implemented");
   }
   BOTAN_ASSERT_UNREACHABLE();
}

namespace {

template <typename T>
T from_first_n_bits(const uint32_t nbits, std::span<const uint8_t> bytes) {
   using wrapped_type = typename T::wrapped_type;

   constexpr const auto outsize = sizeof(wrapped_type);
   BOTAN_ASSERT_NOMSG(nbits <= bytes.size() * 8);
   BOTAN_ASSERT_NOMSG(bytes.size() <= outsize);

   // The input buffer might shorter than the byte-length of the desired
   // integer type. This prepends \0-bytes accordingly.
   std::array<uint8_t, outsize> normalized_bytes = {};
   std::copy(bytes.rbegin(), bytes.rend(), normalized_bytes.rbegin());
   const auto bits = load_be<wrapped_type>(normalized_bytes.data(), 0);

   return T(bits & (~wrapped_type(0) >> (8 * outsize - nbits)));
}

}  // namespace

std::tuple<SphincsHashedMessage, XmssTreeIndexInLayer, TreeNodeIndex> Sphincs_Hash_Functions::H_msg(
   StrongSpan<const SphincsMessageRandomness> r, const SphincsTreeNode& root, const SphincsMessageInternal& message) {
   const auto digest = H_msg_digest(r, root, message);

   // The following calculates the message digest and indices from the
   // raw message digest. See FIPS 205, Algorithm 19, Line 5-10.
   const auto& p = m_sphincs_params;
   BufferSlicer s(digest);
   auto msg_hash = s.copy<SphincsHashedMessage>(p.fors_message_bytes());
   auto tree_index_bytes = s.take(p.tree_digest_bytes());
   auto leaf_index_bytes = s.take(p.leaf_digest_bytes());
   BOTAN_ASSERT_NOMSG(s.empty());

   auto tree_index = from_first_n_bits<XmssTreeIndexInLayer>(p.h() - p.xmss_tree_height(), tree_index_bytes);
   auto leaf_index = from_first_n_bits<TreeNodeIndex>(p.xmss_tree_height(), leaf_index_bytes);
   return {std::move(msg_hash), tree_index, leaf_index};
}

}  // namespace Botan
