/*
 * XMSS WOTS Public and Private Key

 * A Winternitz One Time Signature public/private key for use with
 * Extended Hash-Based Signatures.
 *
 * (C) 2016,2017,2018 Matthias Gierlings
 *     2023           René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_wots.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/xmss_address.h>
#include <botan/internal/xmss_tools.h>

namespace Botan {

namespace {

/**
 * Algorithm 2: Chaining Function.
 *
 * Takes an n-byte input string and transforms it into a the function
 * result iterating the cryptographic hash function "F" steps times on
 * the input x using the outputs of the PRNG "G".
 *
 * This overload is used in multithreaded scenarios, where it is
 * required to provide seperate instances of XMSS_Hash to each
 * thread.
 *
 * @param params      The WOTS parameters to use
 * @param[out] result An n-byte input string, that will be transformed into
 *                    the chaining function result.
 * @param start_idx The start index.
 * @param steps A number of steps.
 * @param adrs An OTS Hash Address.
 * @param seed A seed.
 * @param hash Instance of XMSS_Hash, that may only by the thread
 *             executing chain.
 **/
void chain(const XMSS_WOTS_Parameters& params,
           secure_vector<uint8_t>& result,
           size_t start_idx,
           size_t steps,
           XMSS_Address& adrs,
           std::span<const uint8_t> seed,
           XMSS_Hash& hash) {
   BOTAN_ASSERT_NOMSG(result.size() == hash.output_length());
   BOTAN_ASSERT_NOMSG(start_idx + steps < params.wots_parameter());
   secure_vector<uint8_t> prf_output(hash.output_length());

   // Note that RFC 8391 defines this algorithm recursively (building up the
   // iterations before any calculation) using 'steps' as the iterator and a
   // recursion base with 'steps == 0'.
   // Instead, we implement it iteratively using 'i' as iterator. This makes
   // 'adrs.set_hash_address(i)' equivalent to 'ADRS.setHashAddress(i + s - 1)'.
   for(size_t i = start_idx; i < (start_idx + steps) && i < params.wots_parameter(); i++) {
      adrs.set_hash_address(static_cast<uint32_t>(i));

      // Calculate tmp XOR bitmask
      adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_Mode);
      hash.prf(prf_output, seed, adrs.bytes());
      xor_buf(result.data(), prf_output.data(), result.size());

      // Calculate key
      adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);

      // Calculate f(key, tmp XOR bitmask)
      hash.prf(prf_output, seed, adrs.bytes());
      hash.f(result, prf_output, result);
   }
}

}  // namespace

XMSS_WOTS_PublicKey::XMSS_WOTS_PublicKey(XMSS_WOTS_Parameters params,
                                         std::span<const uint8_t> public_seed,
                                         const XMSS_WOTS_PrivateKey& private_key,
                                         XMSS_Address& adrs,
                                         XMSS_Hash& hash) :
      XMSS_WOTS_Base(std::move(params), private_key.key_data()) {
   for(size_t i = 0; i < m_params.len(); ++i) {
      adrs.set_chain_address(static_cast<uint32_t>(i));
      chain(m_params, m_key_data[i], 0, m_params.wots_parameter() - 1, adrs, public_seed, hash);
   }
}

XMSS_WOTS_PublicKey::XMSS_WOTS_PublicKey(XMSS_WOTS_Parameters params,
                                         std::span<const uint8_t> public_seed,
                                         wots_keysig_t signature,
                                         const secure_vector<uint8_t>& msg,
                                         XMSS_Address& adrs,
                                         XMSS_Hash& hash) :
      XMSS_WOTS_Base(std::move(params), std::move(signature)) {
   secure_vector<uint8_t> msg_digest{m_params.base_w(msg, m_params.len_1())};

   m_params.append_checksum(msg_digest);

   for(size_t i = 0; i < m_params.len(); i++) {
      adrs.set_chain_address(static_cast<uint32_t>(i));
      chain(m_params,
            m_key_data[i],
            msg_digest[i],
            m_params.wots_parameter() - 1 - msg_digest[i],
            adrs,
            public_seed,
            hash);
   }
}

wots_keysig_t XMSS_WOTS_PrivateKey::sign(const secure_vector<uint8_t>& msg,
                                         std::span<const uint8_t> public_seed,
                                         XMSS_Address& adrs,
                                         XMSS_Hash& hash) {
   secure_vector<uint8_t> msg_digest{m_params.base_w(msg, m_params.len_1())};

   m_params.append_checksum(msg_digest);
   auto sig = this->key_data();

   for(size_t i = 0; i < m_params.len(); i++) {
      adrs.set_chain_address(static_cast<uint32_t>(i));
      chain(m_params, sig[i], 0, msg_digest[i], adrs, public_seed, hash);
   }

   return sig;
}

XMSS_WOTS_PrivateKey::XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters params,
                                           std::span<const uint8_t> public_seed,
                                           std::span<const uint8_t> private_seed,
                                           XMSS_Address adrs,
                                           XMSS_Hash& hash) :
      XMSS_WOTS_Base(std::move(params)) {
   m_key_data.resize(m_params.len());
   for(size_t i = 0; i < m_params.len(); ++i) {
      adrs.set_chain_address(static_cast<uint32_t>(i));
      const auto data = concat<std::vector<uint8_t>>(public_seed, adrs.bytes());
      hash.prf_keygen(m_key_data[i], private_seed, data);
   }
}

// Constructor for legacy XMSS_PrivateKeys
XMSS_WOTS_PrivateKey::XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters params,
                                           std::span<const uint8_t> private_seed,
                                           XMSS_Address adrs,
                                           XMSS_Hash& hash) :
      XMSS_WOTS_Base(std::move(params)) {
   m_key_data.resize(m_params.len());

   secure_vector<uint8_t> r;
   hash.prf(r, private_seed, adrs.bytes());

   for(size_t i = 0; i < m_params.len(); ++i) {
      XMSS_Tools::concat<size_t>(m_key_data[i], i, 32);
      hash.prf(m_key_data[i], r, m_key_data[i]);
   }
}

}  // namespace Botan
