/**
 * HSS - Hierarchical Signatures System (RFC 8554)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_HSS_H_
#define BOTAN_HSS_H_

#include <botan/asn1_obj.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/lms.h>

#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace Botan {

/**
 * @brief The index of a node within a specific LMS tree layer
 */
using HSS_Sig_Idx = Strong<uint64_t, struct HSS_Sig_Idx_, EnableArithmeticWithPlainNumber>;

/**
 * @brief The HSS layer in the HSS multi tree starting at 0 from the root
 */
using HSS_Level = Strong<uint32_t, struct HSS_Level_, EnableArithmeticWithPlainNumber>;

/**
 * @brief The HSS-LMS parameters.
 *
 * See RFC 8554 Section 6.
 */
class BOTAN_TEST_API HSS_LMS_Params final {
   public:
      /**
       * @brief Represents a pair of LMS and LMOTS parameters associated with one LMS tree layer.
       */
      class LMS_LMOTS_Params_Pair final {
         public:
            /**
             * @brief The LMS parameters.
             */
            const LMS_Params& lms_params() const { return m_lms_params; }

            /**
             * @brief The LMOTS parameters.
             */
            const LMOTS_Params& lmots_params() const { return m_lmots_params; }

            /**
             * @brief Construct a new params pair
             */
            LMS_LMOTS_Params_Pair(LMS_Params p_lms_params, LMOTS_Params p_lmots_params) :
                  m_lms_params(std::move(p_lms_params)), m_lmots_params(std::move(p_lmots_params)) {}

         private:
            LMS_Params m_lms_params;
            LMOTS_Params m_lmots_params;
      };

      /**
       * @brief Construct the HSS-LMS parameters from a vector LMS and LM-OTS parameters.
       */
      explicit HSS_LMS_Params(std::vector<LMS_LMOTS_Params_Pair> lm_lmots_params);

      /**
       * @brief Construct the HSS-LMS parameters form an algorithm parameter string.
       *
       * The HSS/LMS instance to use for creating new keys is defined using an algorithm parameter string,
       * i.e. to define which hash function (hash), LMS tree hights (h)
       * and OTS Winternitz coefficient widths (w) to use. The syntax is the following:
       *
       * HSS-LMS(<hash>,HW(<h>,<w>),HW(<h>,<w>),...)
       *
       * e.g. 'HSS-LMS(SHA-256,HW(5,1),HW(5,1))' to use SHA-256 in a two-layer HSS instance
       * with a LMS tree height 5 and w=1. The following parameters are allowed (which are
       * specified in RFC 8554 and draft-fluhrer-lms-more-parm-sets-11):
       *
       * hash: 'SHA-256', 'Truncated(SHA-256,192)', 'SHAKE-256(256)', SHAKE-256(192)
       * h: '5', '10', '15', '20', '25'
       * w: '1', '2', '4', '8'
       *
       * Note: The selected hash function is also used for seed derivation.
       */
      explicit HSS_LMS_Params(std::string_view algo_params);

      /**
       * @brief Returns the LMS an LM-OTS parameters at the specified @p level of the HSS tree.
       */
      const LMS_LMOTS_Params_Pair& params_at_level(HSS_Level level) const { return m_lms_lmots_params.at(level.get()); }

      /**
       * @brief Returns the number of layers the HSS tree has.
       */
      HSS_Level L() const { return checked_cast_to<HSS_Level>(m_lms_lmots_params.size()); }

      /**
       * @brief The maximal number of signatures allowed for these HSS parameters
       */
      HSS_Sig_Idx max_sig_count() const { return m_max_sig_count; }

   private:
      /**
       * @brief Compute the maximal number of signatures
       */
      HSS_Sig_Idx calc_max_sig_count() const;

      std::vector<LMS_LMOTS_Params_Pair> m_lms_lmots_params;
      HSS_Sig_Idx m_max_sig_count;
};

/**
 * @brief The internal HSS-LMS private key.
 *
 * Note that the format is not specified in the RFC 8554,
 * and is Botan specific.
 */
class HSS_LMS_PrivateKeyInternal final {
   public:
      /**
       * @brief Create an internal HSS-LMS private key.
       *
       * @param hss_params The HSS-LMS parameters for the key.
       * @param rng The rng to use.
       */
      HSS_LMS_PrivateKeyInternal(const HSS_LMS_Params& hss_params, RandomNumberGenerator& rng);

      /**
       * @brief Parse a private HSS-LMS key.
       *
       * @param key_bytes The private key bytes to parse.
       * @return The internal HSS-LMS private key.
       * @throws Decoding_Error If parsing the private key fails.
       */
      static std::shared_ptr<HSS_LMS_PrivateKeyInternal> from_bytes_or_throw(std::span<const uint8_t> key_bytes);

      /**
       * @brief Returns the used HSS-LMS parameters.
       */
      const HSS_LMS_Params& hss_params() const { return m_hss_params; }

      /**
       * @brief Returns the key in its encoded format.
       */
      secure_vector<uint8_t> to_bytes() const;

      /**
       * @brief Get the idx of the next signature to generate.
       */
      HSS_Sig_Idx get_idx() const { return m_current_idx; }

      /**
       * @brief Set the idx of the next signature to generate.
       *
       * Note that creating two signatures with the same index is insecure.
       * The index must be lower than hss_params().max_sig_count().
       */
      void set_idx(HSS_Sig_Idx idx);

      /**
       * @brief Create a HSS-LMS signature.
       *
       * See RFC 8554 6.2 - Algorithm 8.
       *
       * For each signature creation the hypertree is computed once
       * again, so no data is stored between multiple signatures. However,
       * storing data between multiple signatures could be an optimization
       * if applications create multiple signatures in one go.
       *
       * @param msg The message to sign.
       */
      std::vector<uint8_t> sign(std::span<const uint8_t> msg);

      /**
       * @brief Create the HSS root LMS tree's LMS_PrivateKey using the HSS-LMS private key.
       *
       * We use the same generation as the reference implementation (https://github.com/cisco/hash-sigs)
       * with SECRET_METHOD==2.
       *
       * @return The LMS private key
       */
      LMS_PrivateKey hss_derive_root_lms_private_key() const;

      /**
       * @brief Returns the size in bytes of a signature created by this key.
       */
      size_t signature_size() const { return m_sig_size; }

      void _const_time_poison() const { CT::poison(m_hss_seed); }

      void _const_time_unpoison() const { CT::unpoison(m_hss_seed); }

   private:
      HSS_LMS_PrivateKeyInternal(HSS_LMS_Params hss_params, LMS_Seed hss_seed, LMS_Identifier identifier);

      /**
       * @brief Get the index of the next signature to generate and
       *        increase the counter by one.
       */
      HSS_Sig_Idx reserve_next_idx();

      /**
       * @brief Returns the size in bytes the key would have in its encoded format.
       */
      size_t size() const;

      /**
       * @brief Derive the seed and identifier of an LMS tree from its parent LMS tree.
       *
       * We use the same generation as the reference implementation (https://github.com/cisco/hash-sigs).
       *
       * @param child_lms_lmots_params The LMS-LMOTS parameter pair of the child tree.
       * @param parent_sk The parent's LMS private key
       * @param parent_q The LMS leaf number the child tree has in its parent tree.
       * @return LMS private key
       */
      static LMS_PrivateKey hss_derive_child_lms_private_key(
         const HSS_LMS_Params::LMS_LMOTS_Params_Pair& child_lms_lmots_params,
         const LMS_PrivateKey& parent_sk,
         LMS_Tree_Node_Idx parent_q);

      HSS_LMS_Params m_hss_params;
      LMS_Seed m_hss_seed;
      LMS_Identifier m_identifier;
      HSS_Sig_Idx m_current_idx;
      const size_t m_sig_size;
};

class HSS_Signature;

/**
 * @brief The internal HSS-LMS public key.
 *
 * Format according to RFC 8554:
 * u32str(L) || pub[0]
 */
class HSS_LMS_PublicKeyInternal final {
   public:
      /**
       * @brief Create the public HSS-LMS key from its private key.
       *
       * @param hss_sk The private HSS-LMS key.
       * @return The internal HSS-LMS public key.
       */
      static HSS_LMS_PublicKeyInternal create(const HSS_LMS_PrivateKeyInternal& hss_sk);

      /**
       * @brief Parse a public HSS-LMS key.
       *
       * @param key_bytes The public key bytes to parse.
       * @return The internal HSS-LMS public key.
       * @throws Decoding_Error If parsing the public key fails.
       */
      static std::shared_ptr<HSS_LMS_PublicKeyInternal> from_bytes_or_throw(std::span<const uint8_t> key_bytes);

      HSS_LMS_PublicKeyInternal(HSS_Level L, LMS_PublicKey top_lms_pub_key) :
            m_L(L), m_top_lms_pub_key(std::move(top_lms_pub_key)) {}

      /**
       * @brief Returns the key in its encoded format.
       */
      std::vector<uint8_t> to_bytes() const;

      /**
       * @brief Returns the public LMS key of the top LMS tree.
       */
      const LMS_PublicKey& lms_pub_key() const { return m_top_lms_pub_key; }

      /**
       * @brief Returns the size in bytes the key would have in its encoded format.
       */
      size_t size() const;

      /**
       * @brief The algorithm identifier for HSS-LMS
       */
      AlgorithmIdentifier algorithm_identifier() const;

      /**
       * @brief The object identifier for HSS-LMS
       */
      OID object_identifier() const;

      /**
       * @brief The algorithm name for HSS-LMS
       */
      std::string algo_name() const { return "HSS-LMS"; }

      /**
       * @brief Verify a HSS-LMS signature.
       *
       * See RFC 8554 6.3.
       *
       * @param msg The signed message.
       * @param sig The already parsed HSS-LMS signature.
       * @return True iff the signature is valid.
       */
      bool verify_signature(std::span<const uint8_t> msg, const HSS_Signature& sig) const;

      void _const_time_unpoison() const { CT::unpoison(m_top_lms_pub_key); }

   private:
      HSS_Level m_L;
      LMS_PublicKey m_top_lms_pub_key;
};

/**
 * @brief A HSS-LMS signature.
 *
 * Format according to RFC 8554:
 * u32str(Nspk) || sig[0] || pub[1] || ... || sig[Nspk-1] || pub[Nspk] || sig[Nspk]
 */
class BOTAN_TEST_API HSS_Signature final {
   public:
      /**
       * @brief A LMS public key signed by the HSS layer above it.
       *
       * signed_pub_key[i] = sig[i] || pub[i+1],
       * for i between 0 and Nspk-1, inclusive.
       */
      class Signed_Pub_Key final {
         public:
            /**
             * @brief Constructor for a new sig-pubkey-pair
             */
            Signed_Pub_Key(LMS_Signature sig, LMS_PublicKey pub);

            /**
             * @brief The signature of the public key
             */
            const LMS_Signature& signature() const { return m_sig; }

            /**
             * @brief The signed public key
             */
            const LMS_PublicKey& public_key() const { return m_pub; }

         private:
            LMS_Signature m_sig;
            LMS_PublicKey m_pub;
      };

      /**
       * @brief Parse a HSS-LMS signature.
       *
       * @param sig_bytes The signature bytes to parse.
       * @return The parsed HSS-LMS signature.
       * @throws Decoding_Error If parsing the signature fails.
       */
      static HSS_Signature from_bytes_or_throw(std::span<const uint8_t> sig_bytes);

      /**
       * @brief Returns the size a signature would have in its encoded format.
       *
       * @param params The HSS-LMS parameters.
       * @return size_t The expected size in bytes.
       */
      static size_t size(const HSS_LMS_Params& params);

      /**
       * @brief Returns the number of signed public keys (Nspk = L-1).
       */
      HSS_Level Nspk() const { return HSS_Level(static_cast<uint32_t>(m_signed_pub_keys.size())); }

      /**
       * @brief Returns the signed LMS key signed by a specific layer.
       *
       * @param layer The layer by which the LMS key is signed.
       * @return The LMS key and the signature by its parent layer.
       */
      const Signed_Pub_Key& signed_pub_key(HSS_Level layer) const { return m_signed_pub_keys.at(layer.get()); }

      /**
       * @brief Returns the LMS signature by the bottom layer of the signed message.
       */
      const LMS_Signature& bottom_sig() const { return m_sig; }

   private:
      /**
       * @brief Private constructor using the individual signature fields.
       */
      HSS_Signature(std::vector<Signed_Pub_Key> signed_pub_keys, LMS_Signature sig) :
            m_signed_pub_keys(std::move(signed_pub_keys)), m_sig(std::move(sig)) {}

      std::vector<Signed_Pub_Key> m_signed_pub_keys;
      LMS_Signature m_sig;
};

}  // namespace Botan

#endif
