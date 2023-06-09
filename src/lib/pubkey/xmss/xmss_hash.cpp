/*
 * XMSS Hash
 * A collection of pseudorandom hash functions required for XMSS and WOTS
 * computations.
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_hash.h>

#include <botan/exceptn.h>
#include <botan/xmss_parameters.h>
#include <botan/internal/fmt.h>

namespace Botan {

XMSS_Hash::XMSS_Hash(const XMSS_Hash& hash) :
      m_hash(hash.m_hash->new_object()),
      m_msg_hash(hash.m_msg_hash->new_object()),
      m_zero_padding(hash.m_zero_padding) {}

XMSS_Hash::XMSS_Hash(const XMSS_Parameters& params) :
      m_hash(HashFunction::create(params.hash_function_name())),
      m_msg_hash(HashFunction::create(params.hash_function_name())),
      m_zero_padding(params.hash_id_size() - 1 /* hash IDs are a single uint8_t */) {
   if(!m_hash || !m_msg_hash) {
      throw Lookup_Error(fmt("XMSS cannot use hash {} because it is unavailable", params.hash_function_name()));
   }

   BOTAN_ASSERT(m_hash->output_length() > 0, "Hash output length of zero is invalid.");
}

void XMSS_Hash::h_msg_init(std::span<const uint8_t> randomness,
                           std::span<const uint8_t> root,
                           std::span<const uint8_t> index_bytes) {
   m_msg_hash->clear();
   m_msg_hash->update(m_zero_padding);
   m_msg_hash->update(0x02);
   m_msg_hash->update(randomness.data(), randomness.size());
   m_msg_hash->update(root.data(), root.size());
   m_msg_hash->update(index_bytes.data(), index_bytes.size());
}

void XMSS_Hash::h_msg_update(std::span<const uint8_t> data) {
   m_msg_hash->update(data.data(), data.size());
}

secure_vector<uint8_t> XMSS_Hash::h_msg_final() {
   return m_msg_hash->final();
}

}  // namespace Botan
