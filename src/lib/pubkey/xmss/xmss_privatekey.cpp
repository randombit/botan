/*
 * XMSS Private Key
 * An XMSS: Extended Hash-Based Signature private key.
 * The XMSS private key does not support the X509 and PKCS7 standard. Instead
 * the raw format described in [1] is used.
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 *
 * (C) 2016,2017,2018 Matthias Gierlings
 * (C) 2019,2026 Jack Lloyd
 * (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/rng.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stateful_key_index_registry.h>
#include <botan/internal/xmss_core_ops.h>
#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmss_signature_operation.h>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif

namespace Botan {

namespace {

// fall back to raw decoding for previous versions, which did not encode an OCTET STRING
secure_vector<uint8_t> extract_raw_private_key(std::span<const uint8_t> key_bits, const XMSS_Parameters& xmss_params) {
   secure_vector<uint8_t> raw_key;

   // The public part of the input key bits was already parsed, so we can
   // decide depending on the buffer length whether this must be BER decoded.
   if(key_bits.size() == xmss_params.raw_private_key_size() ||
      key_bits.size() == xmss_params.raw_legacy_private_key_size()) {
      raw_key.assign(key_bits.begin(), key_bits.end());
   } else {
      BER_Decoder(key_bits).decode(raw_key, ASN1_Type::OctetString).verify_end();
   }

   return raw_key;
}

}  // namespace

class XMSS_PrivateKey_Internal {
   public:
      XMSS_PrivateKey_Internal(const XMSS_Parameters& xmss_params,
                               const XMSS_WOTS_Parameters& wots_params,
                               WOTS_Derivation_Method wots_derivation_method,
                               RandomNumberGenerator& rng) :
            m_xmss_params(xmss_params),
            m_wots_params(wots_params),
            m_wots_derivation_method(wots_derivation_method),
            m_prf(rng.random_vec(xmss_params.element_size())),
            m_private_seed(rng.random_vec(xmss_params.element_size())),
            m_keyid(Stateful_Key_Index_Registry::KeyId("XMSS", m_xmss_params.oid(), m_private_seed, m_prf)) {}

      XMSS_PrivateKey_Internal(const XMSS_Parameters& xmss_params,
                               const XMSS_WOTS_Parameters& wots_params,
                               WOTS_Derivation_Method wots_derivation_method,
                               secure_vector<uint8_t> private_seed,
                               secure_vector<uint8_t> prf) :
            m_xmss_params(xmss_params),
            m_wots_params(wots_params),
            m_wots_derivation_method(wots_derivation_method),
            m_prf(std::move(prf)),
            m_private_seed(std::move(private_seed)),
            m_keyid(Stateful_Key_Index_Registry::KeyId("XMSS", m_xmss_params.oid(), m_private_seed, m_prf)) {}

      XMSS_PrivateKey_Internal(const XMSS_Parameters& xmss_params,
                               const XMSS_WOTS_Parameters& wots_params,
                               std::span<const uint8_t> key_bits) :
            m_xmss_params(xmss_params), m_wots_params(wots_params), m_keyid(/* initialized later*/) {
         /*
         The code requires sizeof(size_t) >= ceil(tree_height / 8)

         Maximum supported tree height is 20, ceil(20/8) == 3, so 4 byte
         size_t is sufficient for all defined parameters, or even a
         (hypothetical) tree height 32, which would be extremely slow to
         compute.
         */
         static_assert(sizeof(size_t) >= 4, "size_t is big enough to support leaf index");

         const secure_vector<uint8_t> raw_key = extract_raw_private_key(key_bits, xmss_params);

         if(raw_key.size() != m_xmss_params.raw_private_key_size() &&
            raw_key.size() != m_xmss_params.raw_legacy_private_key_size()) {
            throw Decoding_Error("Invalid XMSS private key size");
         }

         BufferSlicer s(raw_key);

         // We're not interested in the public key here
         s.skip(m_xmss_params.raw_public_key_size());

         auto unused_leaf_bytes = s.take(sizeof(uint32_t));
         const size_t unused_leaf = load_be<uint32_t>(unused_leaf_bytes.data(), 0);
         if(unused_leaf >= (1ULL << m_xmss_params.tree_height())) {
            throw Decoding_Error("XMSS private key leaf index out of bounds");
         }

         m_prf = s.copy_as_secure_vector(m_xmss_params.element_size());
         m_private_seed = s.copy_as_secure_vector(m_xmss_params.element_size());

         m_keyid = Stateful_Key_Index_Registry::KeyId("XMSS", m_xmss_params.oid(), m_private_seed, m_prf);

         // Note m_keyid must be initialized before set_unused_leaf_index is called!
         set_unused_leaf_index(unused_leaf);

         // Legacy keys generated prior to Botan 3.x don't feature a
         // WOTS+ key derivation method encoded in their private key.
         m_wots_derivation_method =
            (s.empty()) ? WOTS_Derivation_Method::Botan2x : static_cast<WOTS_Derivation_Method>(s.take(1).front());

         BOTAN_ASSERT_NOMSG(s.empty());
      }

      secure_vector<uint8_t> serialize(std::vector<uint8_t> raw_public_key) const {
         std::vector<uint8_t> unused_index(4);
         store_be(static_cast<uint32_t>(unused_leaf_index()), unused_index.data());

         std::vector<uint8_t> wots_derivation_method;
         wots_derivation_method.push_back(static_cast<uint8_t>(m_wots_derivation_method));

         return concat<secure_vector<uint8_t>>(
            raw_public_key, unused_index, m_prf, m_private_seed, wots_derivation_method);
      }

      const secure_vector<uint8_t>& prf_value() const { return m_prf; }

      const secure_vector<uint8_t>& private_seed() { return m_private_seed; }

      const XMSS_WOTS_Parameters& wots_parameters() { return m_wots_params; }

      WOTS_Derivation_Method wots_derivation_method() const { return m_wots_derivation_method; }

      void set_unused_leaf_index(size_t idx) {
         if(idx >= (1ULL << m_xmss_params.tree_height())) {
            throw Decoding_Error("XMSS private key leaf index out of bounds");
         } else {
            Stateful_Key_Index_Registry::global().set_index_lower_bound(m_keyid, idx);
         }
      }

      size_t reserve_unused_leaf_index() {
         const uint64_t idx = Stateful_Key_Index_Registry::global().reserve_next_index(m_keyid);
         if(idx >= m_xmss_params.total_number_of_signatures()) {
            throw Decoding_Error("XMSS private key, one time signatures exhausted");
         }
         // Cast is safe even on 32 bit since total_number_of_signatures will be less
         return static_cast<size_t>(idx);
      }

      size_t unused_leaf_index() const {
         const uint64_t idx = Stateful_Key_Index_Registry::global().current_index(m_keyid);
         return checked_cast_to<size_t>(idx);
      }

      uint64_t remaining_signatures() const {
         const size_t max = m_xmss_params.total_number_of_signatures();
         return Stateful_Key_Index_Registry::global().remaining_operations(m_keyid, max);
      }

   private:
      XMSS_Parameters m_xmss_params;
      XMSS_WOTS_Parameters m_wots_params;
      WOTS_Derivation_Method m_wots_derivation_method;

      secure_vector<uint8_t> m_prf;
      secure_vector<uint8_t> m_private_seed;
      Stateful_Key_Index_Registry::KeyId m_keyid;
};

XMSS_PrivateKey::XMSS_PrivateKey(std::span<const uint8_t> key_bits) :
      XMSS_PublicKey(key_bits),
      m_private(std::make_shared<XMSS_PrivateKey_Internal>(m_xmss_params, m_wots_params, key_bits)) {}

XMSS_PrivateKey::XMSS_PrivateKey(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                                 RandomNumberGenerator& rng,
                                 WOTS_Derivation_Method wots_derivation_method) :
      XMSS_PublicKey(xmss_algo_id, rng),
      m_private(std::make_shared<XMSS_PrivateKey_Internal>(m_xmss_params, m_wots_params, wots_derivation_method, rng)) {
   const XMSS_Address adrs;
   XMSS_Hash hash(m_xmss_params);
   m_root = tree_hash(0, XMSS_PublicKey::m_xmss_params.tree_height(), adrs, hash);
}

XMSS_PrivateKey::XMSS_PrivateKey(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                                 size_t idx_leaf,
                                 secure_vector<uint8_t> wots_priv_seed,
                                 secure_vector<uint8_t> prf,
                                 secure_vector<uint8_t> root,
                                 secure_vector<uint8_t> public_seed,
                                 WOTS_Derivation_Method wots_derivation_method) :
      XMSS_PublicKey(xmss_algo_id, std::move(root), std::move(public_seed)),
      m_private(std::make_shared<XMSS_PrivateKey_Internal>(
         m_xmss_params, m_wots_params, wots_derivation_method, std::move(wots_priv_seed), std::move(prf))) {
   m_private->set_unused_leaf_index(idx_leaf);
   BOTAN_ARG_CHECK(m_private->prf_value().size() == m_xmss_params.element_size(),
                   "XMSS: unexpected byte length of PRF value");
   BOTAN_ARG_CHECK(m_private->private_seed().size() == m_xmss_params.element_size(),
                   "XMSS: unexpected byte length of private seed");
}

secure_vector<uint8_t> XMSS_PrivateKey::tree_hash(uint32_t start_idx,
                                                  size_t target_node_height,
                                                  XMSS_Address adrs,
                                                  XMSS_Hash& hash) const {
   return XMSS_Core_Ops::tree_hash(
      start_idx,
      target_node_height,
      adrs,
      hash,
      m_private->wots_parameters(),
      this->public_seed(),
      [this](XMSS_Address adrs_inner, XMSS_Hash& hash_inner) { return wots_public_key_for(adrs_inner, hash_inner); });
}

XMSS_WOTS_PublicKey XMSS_PrivateKey::wots_public_key_for(const XMSS_Address& adrs, XMSS_Hash& hash) const {
   const auto private_key = wots_private_key_for(adrs, hash);
   return XMSS_WOTS_PublicKey(m_private->wots_parameters(), m_public_seed, private_key, adrs, hash);
}

XMSS_WOTS_PrivateKey XMSS_PrivateKey::wots_private_key_for(const XMSS_Address& adrs, XMSS_Hash& hash) const {
   switch(wots_derivation_method()) {
      case WOTS_Derivation_Method::NIST_SP800_208:
         return XMSS_WOTS_PrivateKey(
            m_private->wots_parameters(), m_public_seed, m_private->private_seed(), adrs, hash);
      case WOTS_Derivation_Method::Botan2x:
         return XMSS_WOTS_PrivateKey(m_private->wots_parameters(), m_private->private_seed(), adrs, hash);
   }

   throw Invalid_State("WOTS derivation method is out of the enum's range");
}

secure_vector<uint8_t> XMSS_PrivateKey::private_key_bits() const {
   return DER_Encoder().encode(raw_private_key(), ASN1_Type::OctetString).get_contents();
}

size_t XMSS_PrivateKey::reserve_unused_leaf_index() {
   return m_private->reserve_unused_leaf_index();
}

size_t XMSS_PrivateKey::unused_leaf_index() const {
   return m_private->unused_leaf_index();
}

size_t XMSS_PrivateKey::remaining_signatures() const {
   return checked_cast_to<size_t>(m_private->remaining_signatures());
}

std::optional<uint64_t> XMSS_PrivateKey::remaining_operations() const {
   return m_private->remaining_signatures();
}

const secure_vector<uint8_t>& XMSS_PrivateKey::prf_value() const {
   return m_private->prf_value();
}

secure_vector<uint8_t> XMSS_PrivateKey::raw_private_key() const {
   return m_private->serialize(raw_public_key());
}

WOTS_Derivation_Method XMSS_PrivateKey::wots_derivation_method() const {
   return m_private->wots_derivation_method();
}

std::unique_ptr<Public_Key> XMSS_PrivateKey::public_key() const {
   return std::make_unique<XMSS_PublicKey>(xmss_parameters().oid(), root(), public_seed());
}

std::unique_ptr<PK_Ops::Signature> XMSS_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                        std::string_view /*params*/,
                                                                        std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<XMSS_Signature_Operation>(*this);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
