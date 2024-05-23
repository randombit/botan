/**
 * LMS - Leighton-Micali Hash-Based Signatures (RFC 8554)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_LMS_H_
#define BOTAN_LMS_H_

#include <botan/internal/lm_ots.h>

#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace Botan {

/**
 * @brief Enum of available LMS algorithm types.
 *
 * The supported parameter sets are defined in RFC 8554 Section 5.1. and
 * draft-fluhrer-lms-more-parm-sets-11 Section 5. HSS/LMS typecodes are
 * introduced in RFC 8554 Section 3.2. and their format specified in
 * Section 3.3.
 */
enum class LMS_Algorithm_Type : uint32_t {
   // --- RFC 8554 ---
   RESERVED = 0x00,

   // SHA-256 based
   SHA256_M32_H5 = 0x05,
   SHA256_M32_H10 = 0x06,
   SHA256_M32_H15 = 0x07,
   SHA256_M32_H20 = 0x08,
   SHA256_M32_H25 = 0x09,

   // --- draft-fluhrer-lms-more-parm-sets-11 ---
   // SHA-256/192 based
   SHA256_M24_H5 = 0x0a,
   SHA256_M24_H10 = 0x0b,
   SHA256_M24_H15 = 0x0c,
   SHA256_M24_H20 = 0x0d,
   SHA256_M24_H25 = 0x0e,

   // SHAKE-256/256 based
   SHAKE_M32_H5 = 0x0f,
   SHAKE_M32_H10 = 0x10,
   SHAKE_M32_H15 = 0x11,
   SHAKE_M32_H20 = 0x12,
   SHAKE_M32_H25 = 0x13,

   // SHAKE-256/192 based
   SHAKE_M24_H5 = 0x14,
   SHAKE_M24_H10 = 0x15,
   SHAKE_M24_H15 = 0x16,
   SHAKE_M24_H20 = 0x17,
   SHAKE_M24_H25 = 0x18
};

/**
 * @brief The length in bytes of the LMS identifier (I).
 */
constexpr size_t LMS_IDENTIFIER_LEN = 16;

/**
 * @brief The authentication path of an LMS signature
 */
using LMS_AuthenticationPath = Strong<std::vector<uint8_t>, struct LMS_AuthenticationPath_>;

/**
 * @brief A node with the LMS tree
 */
using LMS_Tree_Node = Strong<std::vector<uint8_t>, struct LMS_Tree_Node_>;

/**
 * @brief Raw bytes of an LMS signature
 */
using LMS_Signature_Bytes = Strong<std::vector<uint8_t>, struct LMS_Signature_Bytes_>;

/**
 * @brief The LMS parameters.
 *
 * See RFC 8554 Section 5.1.
 */
class BOTAN_TEST_API LMS_Params {
   public:
      /**
       * @brief Create the LMS parameters from a known algorithm type.
       * @throws Decoding_Error If the algorithm type is unknown
       */
      static LMS_Params create_or_throw(LMS_Algorithm_Type type);

      /**
       * @brief Create the LMS parameters from a hash function and tree height.
       *
       * @param hash_name The name of the hash function to use.
       * @param h The height of the tree.
       * @throws Decoding_Error If the algorithm type is unknown
       */
      static LMS_Params create_or_throw(std::string_view hash_name, uint8_t h);

      /**
       * @brief Retuns the LMS algorithm type.
       */
      LMS_Algorithm_Type algorithm_type() const { return m_algorithm_type; }

      /**
       * @brief Returns the height of the LMS tree.
       */
      uint8_t h() const { return m_h; }

      /**
       * @brief Returns the number of bytes associated with each node.
       */
      size_t m() const { return m_m; }

      /**
       * @brief Returns the name of the hash function to use.
       */
      const std::string& hash_name() const { return m_hash_name; }

      /**
       * @brief Construct a new hash instance for the LMS instance.
       */
      std::unique_ptr<HashFunction> hash() const { return HashFunction::create_or_throw(hash_name()); }

   private:
      /**
       * @brief Construct a new LMS parameter object.
       *
       * @param algorithm_type The algorithm type.
       * @param hash_name The name of the hash function to use.
       * @param h The height of the tree.
       */
      LMS_Params(LMS_Algorithm_Type algorithm_type, std::string_view hash_name, uint8_t h);

      LMS_Algorithm_Type m_algorithm_type;
      uint8_t m_h;
      size_t m_m;
      std::string m_hash_name;
};

/**
 * @brief Base class for LMS private and public key. Contains public data associated with this
 *        LMS instance.
 */
class BOTAN_TEST_API LMS_Instance {
   public:
      /**
       * @brief Constructor storing the provided LMS data.
       */
      LMS_Instance(LMS_Params lms_params, LMOTS_Params lmots_params, LMS_Identifier identifier) :
            m_lms_params(std::move(lms_params)),
            m_lmots_params(std::move(lmots_params)),
            m_identifier(std::move(identifier)) {}

      /**
       * @brief The LMS parameters for this LMS instance.
       */
      const LMS_Params& lms_params() const { return m_lms_params; }

      /**
       * @brief The LMOTS parameters used for OTS instances of this LMS instance.
       */
      const LMOTS_Params& lmots_params() const { return m_lmots_params; }

      /**
       * @brief The identifier of this LMS tree ('I' in RFC 8554)
       */
      const LMS_Identifier& identifier() const { return m_identifier; }

   private:
      LMS_Params m_lms_params;
      LMOTS_Params m_lmots_params;
      LMS_Identifier m_identifier;
};

class LMS_PublicKey;

/**
 * @brief Representation of an LMS Private key
 *
 * Contains the secret seed used for OTS key derivation
 * as described in RFC 8554 Appendix A.
 */
class BOTAN_TEST_API LMS_PrivateKey : public LMS_Instance {
   public:
      /**
       * @brief Construct storing the LMS instance data and the secret seed
       */
      LMS_PrivateKey(LMS_Params lms_params, LMOTS_Params lmots_params, LMS_Identifier I, LMS_Seed seed) :
            LMS_Instance(std::move(lms_params), std::move(lmots_params), std::move(I)), m_seed(std::move(seed)) {}

      /**
       * @brief The secret seed used for LMOTS' WOTS chain input creation (RFC 8554 Appendix A)
       */
      const LMS_Seed& seed() const { return m_seed; }

      /**
       * @brief Sign a message using an LMS_PrivateKey and the used leaf index (RFC 8554 5.4.1).
       *
       * The signature is written in the provided buffer. The LMS_PublicKey
       * associated with the given private key is returned.
       */
      LMS_PublicKey sign_and_get_pk(StrongSpan<LMS_Signature_Bytes> out_sig,
                                    LMS_Tree_Node_Idx q,
                                    const LMS_Message& msg) const;

   private:
      LMS_Seed m_seed;
};

class LMS_Signature;

/**
 * @brief The LMS public key.
 *
 * Format according to RFC 8554:
 * u32str(type) || u32str(otstype) || I || T[1]
 */
class BOTAN_TEST_API LMS_PublicKey : public LMS_Instance {
   public:
      /**
       * @brief Parse a public LMS key.
       *
       * @param slicer The BufferSlicer at the public key bytes' position
       * @return The LMS public key.
       * @throws Decoding_Error If parsing the public key fails.
       */
      static LMS_PublicKey from_bytes_or_throw(BufferSlicer& slicer);

      /**
       * @brief Construct a public key for given public key data
       */
      LMS_PublicKey(LMS_Params lms_params, LMOTS_Params lmots_params, LMS_Identifier I, LMS_Tree_Node lms_root);

      /**
       * @brief Construct a new public key from a given LMS private key (RFC 8554 5.3).
       */
      LMS_PublicKey(const LMS_PrivateKey& sk);

      /**
       * @brief Bytes of the full lms public key according to 8554 5.3
       *
       * pub_key_bytes = u32str(type) || u32str(otstype) || I || T[1]
       */
      std::vector<uint8_t> to_bytes() const;

      /**
       * @brief The expected size of an LMS public key for given @p lms_params
       */
      static size_t size(const LMS_Params& lms_params);

      /**
       * @brief Verify a LMS signature.
       *
       * See RFC 8554 5.4.2 - Algorithm 6.
       *
       * @param msg The signed message.
       * @param sig The already parsed LMS signature.
       * @return True if the signature is valid, false otherwise.
       */
      bool verify_signature(const LMS_Message& msg, const LMS_Signature& sig) const;

   private:
      /**
       * @brief Compute an lms public key candidate.
       *
       * Given the LMS public key, a LMS-Signature-LMS_Message pair, compute
       * an LMS public key candidate as described in RFC 8554 5.4.2 Algorithm 6a.
       */
      std::optional<LMS_Tree_Node> lms_compute_root_from_sig(const LMS_Message& msg, const LMS_Signature& sig) const;

      /**
       * @brief Root node of the LMS tree ('T[1]' in RFC 8554 5.3)
       */
      const LMS_Tree_Node& lms_root() const { return m_lms_root; }

      LMS_Tree_Node m_lms_root;
};

/**
 * @brief Container for LMS Signature data.
 *
 * Contains a method for secure signature parsing.
 */
class BOTAN_TEST_API LMS_Signature {
   public:
      /**
       * @brief Parse the bytes of a lms signature into a LMS Signature object
       *
       * @param slicer A BufferSlicer object at the position of the LMS_Signature to parse
       * @return LMS_Signature object
       * @throws Decoding_Error If parsing the signature fails.
       */
      static LMS_Signature from_bytes_or_throw(BufferSlicer& slicer);

      /**
       * @brief The index of the signing leaf given by the signature
       */
      LMS_Tree_Node_Idx q() const { return m_q; }

      /**
       * @brief The LMOTS signature object containing the parsed LMOTS signature bytes
       *        contained in the LMS signature
       */
      const LMOTS_Signature& lmots_sig() const { return m_lmots_sig; }

      /**
       * @brief The LMS algorithm type given by the signature
       */
      LMS_Algorithm_Type lms_type() const { return m_lms_type; }

      /**
       * @brief The authentication path bytes given by the signature
       *
       * ('path[0] || ... || path[h-1]' in RFC 8554 5.4)
       */
      StrongSpan<const LMS_AuthenticationPath> auth_path() const { return m_auth_path; }

      /**
       * @return size_t The expected size of the signature.
       */
      static size_t size(const LMS_Params& lms_params, const LMOTS_Params& lmots_params);

   private:
      /**
       * @brief Private constructor storing the data fields individually
       */
      LMS_Signature(LMS_Tree_Node_Idx q,
                    LMOTS_Signature lmots_sig,
                    LMS_Algorithm_Type lms_type,
                    LMS_AuthenticationPath auth_path) :
            m_q(q), m_lmots_sig(std::move(lmots_sig)), m_lms_type(lms_type), m_auth_path(std::move(auth_path)) {}

      LMS_Tree_Node_Idx m_q;
      LMOTS_Signature m_lmots_sig;
      LMS_Algorithm_Type m_lms_type;
      LMS_AuthenticationPath m_auth_path;
};

}  // namespace Botan

#endif
