/**
 * LM-OTS - Leighton-Micali One-Time Signatures (RFC 8554 Section 4)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_LM_OTS_H_
#define BOTAN_LM_OTS_H_

#include <botan/hash.h>
#include <botan/internal/stl_util.h>

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

/**
 * @brief Seed of the LMS tree, used to generate the LM-OTS private keys.
 */
using LMS_Seed = Strong<secure_vector<uint8_t>, struct LMS_SEED_>;

/**
 * @brief One node within one LM-OTS hash chain.
 */
using LMOTS_Node = Strong<secure_vector<uint8_t>, struct LMOTS_Node_>;

/**
 * @brief The K value from the LM-OTS public key.
 */
using LMOTS_K = Strong<std::vector<uint8_t>, struct LMOTS_K_>;

/**
 * @brief Byte vector of an LM-OTS signature.
 */
using LMOTS_Signature_Bytes = Strong<std::vector<uint8_t>, struct LMOTS_Signature_Bytes_>;

/**
 * @brief The index of a node within a specific LMS tree layer
 */
using LMS_Tree_Node_Idx = Strong<uint32_t, struct LMS_Tree_Node_Idx_, EnableArithmeticWithPlainNumber>;

/**
 * @brief The identifier of an LMS tree (I in RFC 8554)
 */
using LMS_Identifier = Strong<std::vector<uint8_t>, struct LMS_Identifier_>;

/**
 * @brief A message that is signed with an LMS tree
 */
using LMS_Message = Strong<std::vector<uint8_t>, struct LMS_Message_>;

/**
 * @brief Enum of available LM-OTS algorithm types.
 *
 * The supported parameter sets are defined in RFC 8554 Section 4.1. and
 * draft-fluhrer-lms-more-parm-sets-11 Section 4. HSS/LMS typecodes are
 * introduced in RFC 8554 Section 3.2. and their format specified in
 * Section 3.3.
 */
enum class LMOTS_Algorithm_Type : uint32_t {
   // --- RFC 8554 ---
   RESERVED = 0x00,

   // SHA-256 based
   SHA256_N32_W1 = 0x01,
   SHA256_N32_W2 = 0x02,
   SHA256_N32_W4 = 0x03,
   SHA256_N32_W8 = 0x04,

   // --- draft-fluhrer-lms-more-parm-sets-11 ---
   // SHA-256/192 based
   SHA256_N24_W1 = 0x05,
   SHA256_N24_W2 = 0x06,
   SHA256_N24_W4 = 0x07,
   SHA256_N24_W8 = 0x08,

   // SHAKE-256/256 based
   SHAKE_N32_W1 = 0x09,
   SHAKE_N32_W2 = 0x0a,
   SHAKE_N32_W4 = 0x0b,
   SHAKE_N32_W8 = 0x0c,

   // SHAKE-256/192 based
   SHAKE_N24_W1 = 0x0d,
   SHAKE_N24_W2 = 0x0e,
   SHAKE_N24_W4 = 0x0f,
   SHAKE_N24_W8 = 0x10,
};

/**
 * @brief The LM-OTS parameters.
 *
 * See RFC 8554 Section 4.1.
 */
class BOTAN_TEST_API LMOTS_Params final {
   public:
      /**
       * @brief Create the LM-OTS parameters from a known algorithm type.
       * @throws Decoding_Error If the algorithm type is unknown
       */
      static LMOTS_Params create_or_throw(LMOTS_Algorithm_Type type);

      /**
       * @brief Create the LM-OTS parameters from a hash function and width.
       *
       * @param hash_name tha name of the hash function to use.
       * @param w the width (in bits) of the Winternitz coefficients.
       * @throws Decoding_Error If the algorithm type is unknown
       */
      static LMOTS_Params create_or_throw(std::string_view hash_name, uint8_t w);

      /**
       * @brief Returns the LM-OTS algorithm type.
       */
      LMOTS_Algorithm_Type algorithm_type() const { return m_algorithm_type; }

      /**
       * @brief The number of bytes of the output of the hash function.
       */
      size_t n() const { return m_n; }

      /**
       * @brief The width (in bits) of the Winternitz coefficients.
       */
      uint8_t w() const { return m_w; }

      /**
       * @brief The maximum the winternitz coefficients can have.
       */
      uint8_t coef_max() const { return (1 << m_w) - 1; }

      /**
       * @brief The number of n-byte string elements that make up the LM-OTS signature.
       */
      uint16_t p() const { return m_p; }

      /**
       * @brief The number of left-shift bits used in the checksum function Cksm.
       */
      uint8_t ls() const { return m_ls; }

      /**
       * @brief Name of the hash function to use.
       */
      const std::string& hash_name() const { return m_hash_name; }

      /**
       * @brief Construct a new hash instance for the OTS instance.
       */
      std::unique_ptr<HashFunction> hash() const { return HashFunction::create_or_throw(hash_name()); }

   private:
      /**
       * @brief Construct a new LM-OTS parameter object.
       *
       * @param algorithm_type The algorithm type.
       * @param hash_name The name of the hash function to use.
       * @param w The width (in bits) of the Winternitz coefficients.
       */
      LMOTS_Params(LMOTS_Algorithm_Type algorithm_type, std::string_view hash_name, uint8_t w);

      LMOTS_Algorithm_Type m_algorithm_type;
      size_t m_n;
      uint8_t m_w;
      uint16_t m_p;
      uint8_t m_ls;
      std::string m_hash_name;
};

/**
 * @brief Representation of a LM-OTS signature.
 */
class BOTAN_TEST_API LMOTS_Signature final {
   public:
      /**
       * @brief Parse a LM-OTS signature.
       *
       * @param slicer The private key bytes to parse.
       * @return The LM-OTS signature.
       * @throws Decoding_Error If parsing the signature fails.
       */
      static LMOTS_Signature from_bytes_or_throw(BufferSlicer& slicer);

      /**
       * @brief Returns the LM-OTS algorithm type.
       */
      LMOTS_Algorithm_Type algorithm_type() const { return m_algorithm_type; }

      /**
       * @brief The n-byte randomizer of the signature.
       */
      std::span<const uint8_t> C() const { return m_C; }

      /**
       * @brief Returns the part of the signature for @p chain_idx.
       */
      StrongSpan<const LMOTS_Node> y(uint16_t chain_idx) const { return m_y.at(chain_idx); }

      /**
       * @brief The expected size of the signature.
       */
      static size_t size(const LMOTS_Params& params) { return 4 + params.n() * (params.p() + 1); }

   private:
      LMOTS_Signature(LMOTS_Algorithm_Type lmots_type, std::vector<uint8_t> C, std::vector<uint8_t> y_buffer);

      LMOTS_Algorithm_Type m_algorithm_type;
      std::vector<uint8_t> m_C;
      std::vector<uint8_t> m_y_buffer;
      std::vector<StrongSpan<const LMOTS_Node>> m_y;
};

/**
 * @brief Base class for LMOTS private and public key. Contains the parameters for
 *        the specific OTS instance
 */
class BOTAN_TEST_API OTS_Instance {
   public:
      /**
       * @brief Constructor storing the specific OTS parameters
       */
      OTS_Instance(const LMOTS_Params& params, const LMS_Identifier& identifier, LMS_Tree_Node_Idx q) :
            m_params(params), m_identifier(identifier), m_q(q) {}

      /**
       * @brief The LMOTS parameters
       */
      const LMOTS_Params& params() const { return m_params; }

      /**
       * @brief The LMS identifier of the LMS tree containing this OTS instance ('I' in RFC 8554)
       */
      const LMS_Identifier& identifier() const { return m_identifier; }

      /**
       * @brief The index of the LMS tree leaf associated with this OTS instance
       */
      LMS_Tree_Node_Idx q() const { return m_q; }

   private:
      LMOTS_Params m_params;
      LMS_Identifier m_identifier;
      LMS_Tree_Node_Idx m_q;
};

/**
 * @brief Representation of an LMOTS private key.
 *
 * Contains the OTS params, I, q, the secret LMS seed and its derived
 * secret chain inputs (x[] in RFC 8554 4.2)
 */
class BOTAN_TEST_API LMOTS_Private_Key final : public OTS_Instance {
   public:
      /**
       * @brief Derive a LMOTS private key for a given @p seed.
       *
       * Implements RFC 8554 4.2 using derivation of Appendix A
       */
      LMOTS_Private_Key(const LMOTS_Params& params,
                        const LMS_Identifier& identifier,
                        LMS_Tree_Node_Idx q,
                        const LMS_Seed& seed);

      /**
       * @brief The secret chain input at a given chain index. (x[] in RFC 8554 4.2).
       */
      const LMOTS_Node& chain_input(uint16_t chain_idx) const { return m_ots_sk.at(chain_idx); }

      /**
       * @brief Generate a new LMOTS signature.
       *
       * Defined in RFC 8554 4.5
       */
      void sign(StrongSpan<LMOTS_Signature_Bytes> out_sig, const LMS_Message& msg) const;

   private:
      /**
       * @brief Derive random value C
       *
       * Derive the randomized value C as in the reference implementation (cisco):
       * C = HASH(I || Q || 0xFFFD || 0xFF || SEED)
       *
       * Note that this derivation is important if we do not store the signature of root LMS nodes
       * in the private key. Otherwise these root nodes are signed twice with different C values,
       * resulting in a broken OTS signature.
       */
      void derive_random_C(std::span<uint8_t> out, HashFunction& hash) const;

      LMS_Seed m_seed;
      std::vector<LMOTS_Node> m_ots_sk;
};

/**
 * @brief Representation of an OTS public key.
 *
 * Contains the public key bytes
 * as defined in RFC 8554 4.3:
 *
 * u32str(type) || I || u32str(q) || K
 */
class BOTAN_TEST_API LMOTS_Public_Key final : public OTS_Instance {
   public:
      /**
       * @brief Derivivation of an LMOTS public key using an LMOTS_Private_Key as defined
       * in RFC 8554 4.3
       */
      LMOTS_Public_Key(const LMOTS_Private_Key& lmots_sk);

      /**
       * @brief Construct a new LMOTS public key object using the bytes.
       *
       * Note that the passed params, identifier and
       * q value should match with the prefix in @p pub_key_bytes.
       */
      LMOTS_Public_Key(const LMOTS_Params& params, const LMS_Identifier& identifier, LMS_Tree_Node_Idx q, LMOTS_K K) :
            OTS_Instance(params, identifier, q), m_K(std::move(K)) {}

      /**
       * @brief The public key final hash value (K in RFC 8554 4.3 )
       *
       * @return const LMOTS_K&
       */
      const LMOTS_K& K() const { return m_K; }

   private:
      LMOTS_K m_K;
};

/**
 * @brief Compute a public key candidate for an OTS-signature-message pair and the OTS instance parameters.
 *
 * Defined in RFC 8554 4.6 - Algorithm 4b
 */
BOTAN_TEST_API LMOTS_K lmots_compute_pubkey_from_sig(const LMOTS_Signature& sig,
                                                     const LMS_Message& msg,
                                                     const LMS_Identifier& identifier,
                                                     LMS_Tree_Node_Idx q);

}  // namespace Botan

#endif
