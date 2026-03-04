/*
 * XMSS^MT Verification Operation
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSSMT_VERIFICATION_OPERATION_H_
#define BOTAN_XMSSMT_VERIFICATION_OPERATION_H_

#include <botan/pk_ops.h>
#include <botan/xmssmt.h>
#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmssmt_signature.h>

namespace Botan {

/**
 * Provides signature verification capabilities for Extended Hash-Based
 * Signatures (XMSS^MT).
 **/
class XMSSMT_Verification_Operation final : public virtual PK_Ops::Verification {
   public:
      explicit XMSSMT_Verification_Operation(const XMSSMT_PublicKey& public_key);

      bool is_valid_signature(std::span<const uint8_t> sign) override;

      void update(std::span<const uint8_t> input) override;

      std::string hash_function() const override { return m_hash.hash_function(); }

   private:
      /**
       * Algorithm 17: "XMSSMT_verify"
       * Verifies a XMSS^MT signature using the corresponding XMSS^MT public key.
       *
       * @param sig A XMSS^MT signature.
       * @param msg The message signed with sig.
       * @param pub_key the public key
       *
       * @return true if signature sig is valid for msg, false otherwise.
       **/
      bool verify(const XMSSMT_Signature& sig, const secure_vector<uint8_t>& msg, const XMSSMT_PublicKey& pub_key);

      const XMSSMT_PublicKey m_pub_key;
      XMSS_Hash m_hash;
      secure_vector<uint8_t> m_msg_buf;
};

}  // namespace Botan

#endif
