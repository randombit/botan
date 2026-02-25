/*
 * XMSS^MT Signature Operation
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSSMT_SIGNATURE_OPERATION_H_
#define BOTAN_XMSSMT_SIGNATURE_OPERATION_H_

#include <botan/pk_ops.h>
#include <botan/xmssmt.h>
#include <botan/internal/xmss_address.h>
#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmss_wots.h>
#include <botan/internal/xmssmt_signature.h>

namespace Botan {

/**
 * Signature generation operation for Extended Hash-Based Signatures (XMSS^MT) as
 * defined in:
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 **/
class XMSSMT_Signature_Operation final : public virtual PK_Ops::Signature {
   public:
      explicit XMSSMT_Signature_Operation(const XMSSMT_PrivateKey& private_key);

      /**
       * Creates an XMSS^MT signature for the message provided through call to
       * update().
       *
       * @return serialized XMSS^MT signature.
       **/
      std::vector<uint8_t> sign(RandomNumberGenerator& rng) override;

      void update(std::span<const uint8_t> input) override;

      size_t signature_length() const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_hash.hash_function(); }

   private:
      XMSS_TreeSignature generate_tree_signature(const secure_vector<uint8_t>& msg,
                                                 XMSS_Address& adrs,
                                                 uint32_t idx_leaf);

      /* The code is structured to compute the authpath via multiple treehash()-calls on distinct subtrees.
      This means the root node is not computed along the way.
      Instead of calling treehash again to obtain the root (inefficient, recomputes the tree), we have this helper function to simply "hash up the auth path" as we would do for verification.
      A more efficient approach would be to keep track of the required internal nodes.
      */
      secure_vector<uint8_t> root_from_signature(const XMSS_TreeSignature& tree_sig,
                                                 const secure_vector<uint8_t>& msg,
                                                 const XMSS_Address& adrs,
                                                 uint32_t leaf_idx);

      wots_keysig_t build_auth_path(uint32_t idx_leaf, const XMSS_Address& adrs);

      void initialize();

      XMSSMT_PrivateKey m_priv_key;
      XMSS_Hash m_hash;
      secure_vector<uint8_t> m_randomness;
      uint64_t m_leaf_idx;
      bool m_is_initialized;
};

}  // namespace Botan

#endif
