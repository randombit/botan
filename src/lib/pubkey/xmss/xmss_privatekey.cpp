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
#include <botan/mutex.h>
#include <botan/pk_options.h>
#include <botan/rng.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/merkle_tree.h>
#include <botan/internal/pk_options_impl.h>
#include <botan/internal/stateful_key_index_registry.h>
#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmss_signature_operation.h>
#include <botan/internal/xmss_tree_builder.h>
#include <algorithm>
#include <array>
#include <memory>
#include <optional>

namespace Botan {

namespace {

/**
 * Tag of a section holding the lowest row of the treetop
 */
constexpr uint32_t XMSS_SECTION_TREETOP = 1;

enum class XMSS_PrivateKey_Format : uint8_t {
   /** The fields up to the WOTS+ derivation method only, wrapped in an OCTET STRING (OID XMSS) */
   // TODO(Botan4) Remove the legacy format
   Legacy,
   /** Additionally the cached tree data (OID XMSS-Private-Key) */
   Current,
   /** Raw bytes, which carry no OID: either of the above */
   // TODO(Botan4) Remove; raw bytes are then always in the current format
   Either,
};

XMSS_PrivateKey_Format private_key_format(const AlgorithmIdentifier& alg_id) {
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for XMSS private key");
   }

   // TODO(Botan4) Remove the legacy format, and accept only the current one
   const auto& oid = alg_id.oid();
   if(oid.empty()) {
      return XMSS_PrivateKey_Format::Either;
   } else if(oid == OID::from_string("XMSS")) {
      return XMSS_PrivateKey_Format::Legacy;
   } else if(oid == OID::from_string("XMSS-Private-Key")) {
      return XMSS_PrivateKey_Format::Current;
   } else {
      throw Decoding_Error("Unexpected OID for XMSS private key");
   }
}

// The raw key starts with the OID of the XMSS parameters, so its first byte is never 0x04
bool is_wrapped_in_octet_string(std::span<const uint8_t> key_bits) {
   return !key_bits.empty() && key_bits[0] == static_cast<uint8_t>(ASN1_Type::OctetString);
}

// TODO(Botan4) Remove the legacy format
bool is_legacy_encoding(std::span<const uint8_t> key_bits) {
   if(is_wrapped_in_octet_string(key_bits)) {
      return true;
   }
   if(key_bits.size() < sizeof(uint32_t)) {
      throw Decoding_Error("Invalid XMSS private key size");
   }
   const auto params =
      XMSS_Parameters::from_id(static_cast<XMSS_Parameters::xmss_algorithm_t>(load_be<uint32_t>(key_bits.data(), 0)));
   return key_bits.size() == params._raw_private_key_size() || key_bits.size() == params._raw_legacy_private_key_size();
}

// fall back to raw decoding for previous versions, which did not encode an OCTET STRING
secure_vector<uint8_t> extract_raw_legacy_private_key(std::span<const uint8_t> key_bits) {
   if(is_wrapped_in_octet_string(key_bits)) {
      secure_vector<uint8_t> raw_key;
      BER_Decoder(key_bits, BER_Decoder::Limits::DER()).decode(raw_key, ASN1_Type::OctetString).verify_end();
      return raw_key;
   }
   return secure_vector<uint8_t>(key_bits.begin(), key_bits.end());
}

bool is_known_wots_derivation_method(WOTS_Derivation_Method method) {
   return method == WOTS_Derivation_Method::Botan2x || method == WOTS_Derivation_Method::NIST_SP800_208;
}

/*
* The identity consists of the inputs to the WOTS+ key derivation, so that
* keys with the same WOTS+ keys share one leaf index. SK_PRF is not one of
* these inputs, and neither is the public seed when using Botan2x derivation.
*/
Stateful_Key_Index_Registry::KeyId xmss_key_id(const XMSS_Parameters& params,
                                               WOTS_Derivation_Method wots_derivation_method,
                                               std::span<const uint8_t> private_seed,
                                               std::span<const uint8_t> public_seed) {
   const auto algo_params = concat<std::vector<uint8_t>>(store_be(static_cast<uint32_t>(params.oid())),
                                                         std::array{static_cast<uint8_t>(wots_derivation_method)});

   const bool derivation_uses_public_seed = (wots_derivation_method == WOTS_Derivation_Method::NIST_SP800_208);

   return Stateful_Key_Index_Registry::KeyId("XMSS",
                                             algo_params,
                                             params.total_number_of_signatures(),
                                             private_seed,
                                             derivation_uses_public_seed ? public_seed : std::span<const uint8_t>());
}

struct XMSS_Encoded_Private_Key {
      XMSS_Parameters::xmss_algorithm_t oid;
      WOTS_Derivation_Method wots_derivation_method;
      secure_vector<uint8_t> root;
      secure_vector<uint8_t> public_seed;
      secure_vector<uint8_t> private_seed;
      secure_vector<uint8_t> prf;
      size_t unused_leaf;
      std::optional<std::vector<uint8_t>> treetop_row;
};

XMSS_Encoded_Private_Key decode_private_key(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   const auto format = private_key_format(alg_id);

   // TODO(Botan4) Remove the legacy format
   const bool legacy = format == XMSS_PrivateKey_Format::Legacy ||
                       (format == XMSS_PrivateKey_Format::Either && is_legacy_encoding(key_bits));

   const secure_vector<uint8_t> raw_key =
      legacy ? extract_raw_legacy_private_key(key_bits) : secure_vector<uint8_t>(key_bits.begin(), key_bits.end());

   BufferSlicer s(raw_key);

   const auto take = [&](size_t len) {
      if(s.remaining() < len) {
         throw Decoding_Error("Invalid XMSS private key size");
      }
      return s.take(len);
   };
   const auto take_u32 = [&]() { return load_be<uint32_t>(take(sizeof(uint32_t)).first<sizeof(uint32_t)>()); };
   const auto copy = [&](size_t len) {
      const auto bytes = take(len);
      return secure_vector<uint8_t>(bytes.begin(), bytes.end());
   };

   const auto oid = static_cast<XMSS_Parameters::xmss_algorithm_t>(take_u32());
   const auto params = XMSS_Parameters::from_id(oid);
   const size_t n = params.element_size();

   if(legacy && raw_key.size() != params._raw_private_key_size() &&
      raw_key.size() != params._raw_legacy_private_key_size()) {
      throw Decoding_Error("Invalid XMSS private key size");
   }

   auto root = copy(n);
   auto public_seed = copy(n);
   const size_t unused_leaf = take_u32();
   auto prf = copy(n);
   auto private_seed = copy(n);

   // Legacy keys generated prior to Botan 3.x don't feature a
   // WOTS+ key derivation method encoded in their private key.
   const auto wots_derivation_method =
      (legacy && s.empty()) ? WOTS_Derivation_Method::Botan2x : static_cast<WOTS_Derivation_Method>(take(1)[0]);

   if(!is_known_wots_derivation_method(wots_derivation_method)) {
      throw Decoding_Error("XMSS private key has an unknown WOTS+ derivation method");
   }

   std::optional<std::vector<uint8_t>> treetop_row;

   if(!legacy) {
      const uint32_t sections = take_u32();
      for(uint32_t i = 0; i != sections; ++i) {
         const uint32_t tag = take_u32();
         const uint32_t length = take_u32();
         const auto body = take(length);

         // Sections with unknown tags are skipped, for forward compatibility
         if(tag == XMSS_SECTION_TREETOP) {
            if(treetop_row.has_value()) {
               throw Decoding_Error("XMSS private key contains more than one cached tree");
            }
            if(length != Merkle_Treetop::row_size(static_cast<uint32_t>(params.tree_height()), n)) {
               throw Decoding_Error("Invalid size of cached tree in XMSS private key");
            }
            treetop_row.emplace(body.begin(), body.end());
         }
      }
   }

   if(!s.empty()) {
      throw Decoding_Error("XMSS private key contains more bytes than expected");
   }

   return XMSS_Encoded_Private_Key{oid,
                                   wots_derivation_method,
                                   std::move(root),
                                   std::move(public_seed),
                                   std::move(private_seed),
                                   std::move(prf),
                                   unused_leaf,
                                   std::move(treetop_row)};
}

}  // namespace

class XMSS_PrivateKey_Internal final {
   public:
      XMSS_PrivateKey_Internal(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                               WOTS_Derivation_Method wots_derivation_method,
                               secure_vector<uint8_t> root,
                               secure_vector<uint8_t> public_seed,
                               secure_vector<uint8_t> private_seed,
                               secure_vector<uint8_t> prf) :
            m_xmss_params(XMSS_Parameters::from_id(xmss_algo_id)),
            m_wots_params(m_xmss_params.wots_parameters()),
            m_wots_derivation_method(wots_derivation_method),
            m_root(std::move(root)),
            m_public_seed(std::move(public_seed)),
            m_prf(std::move(prf)),
            m_private_seed(std::move(private_seed)),
            m_keyid(xmss_key_id(m_xmss_params, m_wots_derivation_method, m_private_seed, m_public_seed)) {
         // Callers update the registry afterwards, so all validation must happen here
         BOTAN_ARG_CHECK(is_known_wots_derivation_method(m_wots_derivation_method),
                         "XMSS: unknown WOTS+ derivation method");
         BOTAN_ARG_CHECK(m_root.size() == m_xmss_params.element_size(), "XMSS: unexpected byte length of root hash");
         BOTAN_ARG_CHECK(m_public_seed.size() == m_xmss_params.element_size(),
                         "XMSS: unexpected byte length of public seed");
         BOTAN_ARG_CHECK(m_prf.size() == m_xmss_params.element_size(), "XMSS: unexpected byte length of PRF value");
         BOTAN_ARG_CHECK(m_private_seed.size() == m_xmss_params.element_size(),
                         "XMSS: unexpected byte length of private seed");
      }

      XMSS_PrivateKey_Internal(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
            XMSS_PrivateKey_Internal(decode_private_key(alg_id, key_bits)) {}

      XMSS_PrivateKey_Internal(const XMSS_PrivateKey_Internal& other) = delete;
      XMSS_PrivateKey_Internal(XMSS_PrivateKey_Internal&& other) = delete;
      XMSS_PrivateKey_Internal& operator=(const XMSS_PrivateKey_Internal& other) = delete;
      XMSS_PrivateKey_Internal& operator=(XMSS_PrivateKey_Internal&& other) = delete;
      ~XMSS_PrivateKey_Internal() = default;

      static std::shared_ptr<XMSS_PrivateKey_Internal> generate(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                                                                RandomNumberGenerator& rng,
                                                                WOTS_Derivation_Method wots_derivation_method) {
         BOTAN_ARG_CHECK(is_known_wots_derivation_method(wots_derivation_method),
                         "XMSS: unknown WOTS+ derivation method");

         const auto params = XMSS_Parameters::from_id(xmss_algo_id);
         const size_t n = params.element_size();

         // The order in which the seeds are drawn from the RNG (public seed, then
         // prf, then private seed) must match the historical two-phase construction
         // so that a deterministic RNG reproduces the same key material.
         auto public_seed = rng.random_vec(n);
         auto prf = rng.random_vec(n);
         auto private_seed = rng.random_vec(n);

         XMSS_Hash hash(params);
         const XMSS_Tree_Builder builder(params.wots_parameters(), wots_derivation_method, public_seed, private_seed);
         auto [treetop, subtree] = builder.merkle_tree(params.tree_height(), XMSS_Address(), hash).build(0);
         const auto root_bytes = treetop.root();
         secure_vector<uint8_t> root(root_bytes.begin(), root_bytes.end());

         auto sk = std::make_shared<XMSS_PrivateKey_Internal>(xmss_algo_id,
                                                              wots_derivation_method,
                                                              std::move(root),
                                                              std::move(public_seed),
                                                              std::move(private_seed),
                                                              std::move(prf));
         sk->m_treetop = std::move(treetop);
         sk->m_subtree = std::move(subtree);
         return sk;
      }

      secure_vector<uint8_t> serialize() const {
         const lock_guard_type<mutex_type> lock(m_cache_mutex);

         const auto oid = store_be(static_cast<uint32_t>(m_xmss_params.oid()));
         const auto unused_index = store_be(checked_cast_to<uint32_t>(unused_leaf_index()));
         const std::array<uint8_t, 1> wots_derivation_method{static_cast<uint8_t>(m_wots_derivation_method)};

         if(!m_treetop.has_value()) {
            return concat<secure_vector<uint8_t>>(oid,
                                                  m_root,
                                                  m_public_seed,
                                                  unused_index,
                                                  m_prf,
                                                  m_private_seed,
                                                  wots_derivation_method,
                                                  store_be(uint32_t(0)));
         }

         const auto row = m_treetop->row();
         return concat<secure_vector<uint8_t>>(oid,
                                               m_root,
                                               m_public_seed,
                                               unused_index,
                                               m_prf,
                                               m_private_seed,
                                               wots_derivation_method,
                                               store_be(uint32_t(1)),
                                               store_be(XMSS_SECTION_TREETOP),
                                               store_be(checked_cast_to<uint32_t>(row.size())),
                                               row);
      }

      size_t reserve_leaf(std::span<uint8_t> auth_path, XMSS_Hash& hash) const {
         const lock_guard_type<mutex_type> lock(m_cache_mutex);

         // Reserving the index while holding the lock means the cache of this
         // object only ever moves forward, even when signing concurrently
         const size_t idx = reserve_unused_leaf_index();
         const auto q = static_cast<uint32_t>(idx);
         const auto tree = merkle_tree(hash);

         if(!populate_cache(tree, q)) {
            // The loaded treetop did not match the seed; start over from the seed alone
            clear_cache_locked();
            if(!populate_cache(tree, q)) {
               throw Internal_Error("XMSS tree computed from the seed is inconsistent");
            }
         }

         m_treetop->auth_path(auth_path, q, m_subtree.has_value() ? &m_subtree.value() : nullptr);
         return idx;
      }

      void discard_cached_tree() const {
         const lock_guard_type<mutex_type> lock(m_cache_mutex);
         clear_cache_locked();
      }

      bool root_matches_seed() const {
         XMSS_Hash hash(m_xmss_params);
         return std::ranges::equal(merkle_tree(hash).root(), m_root);
      }

      const XMSS_Parameters& xmss_parameters() const { return m_xmss_params; }

      const secure_vector<uint8_t>& root() const { return m_root; }

      const secure_vector<uint8_t>& public_seed() const { return m_public_seed; }

      const secure_vector<uint8_t>& prf_value() const { return m_prf; }

      const secure_vector<uint8_t>& private_seed() const { return m_private_seed; }

      const XMSS_WOTS_Parameters& wots_parameters() const { return m_wots_params; }

      WOTS_Derivation_Method wots_derivation_method() const { return m_wots_derivation_method; }

      // The signing state (leaf index) lives in the process-wide
      // Stateful_Key_Index_Registry keyed by m_keyid, not in this object, so the
      // methods that advance it leave *this unchanged and are therefore const.
      void set_unused_leaf_index(size_t idx) const {
         // An index equal to 2^h is valid and denotes an exhausted key
         if(idx > (1ULL << m_xmss_params.tree_height())) {
            throw Decoding_Error("XMSS private key leaf index out of bounds");
         } else {
            Stateful_Key_Index_Registry::global().set_index_lower_bound(m_keyid, idx);
         }
      }

      size_t unused_leaf_index() const {
         const uint64_t idx = Stateful_Key_Index_Registry::global().current_index(m_keyid);
         return checked_cast_to<size_t>(idx);
      }

      uint64_t remaining_signatures() const {
         return Stateful_Key_Index_Registry::global().remaining_operations(m_keyid);
      }

   private:
      explicit XMSS_PrivateKey_Internal(XMSS_Encoded_Private_Key encoded) :
            XMSS_PrivateKey_Internal(encoded.oid,
                                     encoded.wots_derivation_method,
                                     std::move(encoded.root),
                                     std::move(encoded.public_seed),
                                     std::move(encoded.private_seed),
                                     std::move(encoded.prf)) {
         /*
         The code requires sizeof(size_t) >= ceil(tree_height / 8)

         Maximum supported tree height is 20, ceil(20/8) == 3, so 4 byte
         size_t is sufficient for all defined parameters, or even a
         (hypothetical) tree height 32, which would be extremely slow to
         compute.
         */
         static_assert(sizeof(size_t) >= 4, "size_t is big enough to support leaf index");

         if(encoded.treetop_row.has_value()) {
            adopt_encoded_row(encoded.treetop_row.value());
         }

         // This comes last, after every check that can reject the encoding, since
         // it raises the index lower bound shared by all copies of this key.
         set_unused_leaf_index(encoded.unused_leaf);
      }

      size_t reserve_unused_leaf_index() const {
         const auto idx = Stateful_Key_Index_Registry::global().reserve_next_index(m_keyid);
         if(!idx.has_value()) {
            throw Invalid_State("XMSS private key, one time signatures exhausted");
         }
         // Cast is safe even on 32 bit since total_number_of_signatures will be less
         return static_cast<size_t>(idx.value());
      }

      Merkle_Tree_Builder merkle_tree(XMSS_Hash& hash) const {
         return XMSS_Tree_Builder(m_wots_params, m_wots_derivation_method, m_public_seed, m_private_seed)
            .merkle_tree(m_xmss_params.tree_height(), XMSS_Address(), hash);
      }

      /**
       * Keep the treetop read from an encoding if it matches the root
       */
      void adopt_encoded_row(std::span<const uint8_t> row) {
         XMSS_Hash hash(m_xmss_params);
         auto treetop = merkle_tree(hash).treetop_from_row(row);
         if(std::ranges::equal(treetop.root(), m_root)) {
            m_treetop = std::move(treetop);
         }
      }

      /**
       * Make sure the cache holds the nodes needed to sign with leaf @p q
       *
       * @return false if a subtree computed from the seed does not match the treetop
       */
      bool populate_cache(const Merkle_Tree_Builder& tree, uint32_t q) const {
         if(!m_treetop.has_value()) {
            auto [treetop, subtree] = tree.build(q);
            if(!std::ranges::equal(treetop.root(), m_root)) {
               throw Invalid_State("XMSS private key does not match its public key");
            }
            m_treetop = std::move(treetop);
            m_subtree = std::move(subtree);
            return true;
         }

         const uint32_t k = m_treetop->k();
         if(k == 0 || (m_subtree.has_value() && m_subtree->index() == (q >> k))) {
            // When k is zero the treetop is the whole tree
            return true;
         }

         m_subtree = tree.build_subtree(m_treetop.value(), q);
         return m_subtree.has_value();
      }

      void clear_cache_locked() const {
         m_treetop.reset();
         m_subtree.reset();
      }

      XMSS_Parameters m_xmss_params;
      XMSS_WOTS_Parameters m_wots_params;
      WOTS_Derivation_Method m_wots_derivation_method;

      secure_vector<uint8_t> m_root;
      secure_vector<uint8_t> m_public_seed;
      secure_vector<uint8_t> m_prf;
      secure_vector<uint8_t> m_private_seed;
      Stateful_Key_Index_Registry::KeyId m_keyid;

      // The public tree nodes needed for signing; the subtree is the one
      // containing the most recently reserved leaf
      mutable mutex_type m_cache_mutex;
      mutable std::optional<Merkle_Treetop> m_treetop;
      mutable std::optional<Merkle_Subtree> m_subtree;
};

XMSS_PrivateKey::XMSS_PrivateKey(std::span<const uint8_t> key_bits) :
      XMSS_PrivateKey(AlgorithmIdentifier(), key_bits) {}

XMSS_PrivateKey::XMSS_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      XMSS_PrivateKey(std::make_shared<XMSS_PrivateKey_Internal>(alg_id, key_bits)) {}

XMSS_PrivateKey::XMSS_PrivateKey(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                                 RandomNumberGenerator& rng,
                                 WOTS_Derivation_Method wots_derivation_method) :
      XMSS_PrivateKey(XMSS_PrivateKey_Internal::generate(xmss_algo_id, rng, wots_derivation_method)) {}

XMSS_PrivateKey::XMSS_PrivateKey(XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
                                 size_t idx_leaf,
                                 secure_vector<uint8_t> wots_priv_seed,
                                 secure_vector<uint8_t> prf,
                                 secure_vector<uint8_t> root,
                                 secure_vector<uint8_t> public_seed,
                                 WOTS_Derivation_Method wots_derivation_method) :
      XMSS_PrivateKey(std::make_shared<XMSS_PrivateKey_Internal>(xmss_algo_id,
                                                                 wots_derivation_method,
                                                                 std::move(root),
                                                                 std::move(public_seed),
                                                                 std::move(wots_priv_seed),
                                                                 std::move(prf))) {
   m_private->set_unused_leaf_index(idx_leaf);
}

XMSS_PrivateKey::XMSS_PrivateKey(std::shared_ptr<XMSS_PrivateKey_Internal> sk) :
      XMSS_PublicKey(sk->xmss_parameters().oid(), sk->root(), sk->public_seed()), m_private(std::move(sk)) {}

bool XMSS_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool strong) const {
   if(strong) {
      // Check that the stored root is consistent with the seeds by
      // recomputing it. This costs about as much as a key generation.
      return m_private->root_matches_seed();
   }
   return true;
}

XMSS_WOTS_PrivateKey XMSS_PrivateKey::wots_private_key_for(const XMSS_Address& adrs, XMSS_Hash& hash) const {
   return XMSS_Tree_Builder(
             xmss_parameters().wots_parameters(), wots_derivation_method(), public_seed(), m_private->private_seed())
      .wots_private_key_for(adrs, hash);
}

secure_vector<uint8_t> XMSS_PrivateKey::private_key_bits() const {
   return raw_private_key();
}

AlgorithmIdentifier XMSS_PrivateKey::pkcs8_algorithm_identifier() const {
   // The format of the private key is not standardized, so it gets its own OID
   return AlgorithmIdentifier(OID::from_string("XMSS-Private-Key"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

size_t XMSS_PrivateKey::reserve_leaf(std::span<uint8_t> auth_path, XMSS_Hash& hash) const {
   return m_private->reserve_leaf(auth_path, hash);
}

void XMSS_PrivateKey::discard_cached_tree() const {
   m_private->discard_cached_tree();
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
   return m_private->serialize();
}

WOTS_Derivation_Method XMSS_PrivateKey::wots_derivation_method() const {
   return m_private->wots_derivation_method();
}

std::unique_ptr<Public_Key> XMSS_PrivateKey::public_key() const {
   return std::make_unique<XMSS_PublicKey>(xmss_parameters().oid(), root(), public_seed());
}

std::unique_ptr<PK_Ops::Signature> XMSS_PrivateKey::_create_signature_op(
   RandomNumberGenerator& rng, const PK_Signature_Options_Reader& options) const {
   BOTAN_UNUSED(rng);

   validate_for_hash_based_signature(options, "XMSS", xmss_parameters().hash_function_name());
   acknowledge_always_deterministic(options);

   require_software_provider(options, algo_name());

   return std::make_unique<XMSS_Signature_Operation>(*this);
}

}  // namespace Botan
