/**
 * XMSS_WOTS_Verification_Operation.h
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_WOTS_VERIFICATION_OPERATION_H__
#define BOTAN_XMSS_WOTS_VERIFICATION_OPERATION_H__

#include <cstddef>
#include <iterator>
#include <botan/types.h>
#include <botan/internal/pk_ops.h>
#include <botan/internal/xmss_wots_addressed_publickey.h>
#include <botan/internal/xmss_wots_common_ops.h>

namespace Botan {

/**
 * Provides signature verification capabilities for Winternitz One Time
 * Signatures used in Extended Merkle Tree Signatures (XMSS).
 *
 * This operation is not intended for stand-alone use and thus not registered
 * in the Botan algorithm registry.
 **/
class XMSS_WOTS_Verification_Operation
   : public virtual PK_Ops::Verification,
     public XMSS_WOTS_Common_Ops
   {
   public:
      typedef XMSS_WOTS_Addressed_PublicKey Key_Type;

      XMSS_WOTS_Verification_Operation(
         const XMSS_WOTS_Addressed_PublicKey& public_key);

      virtual ~XMSS_WOTS_Verification_Operation() {}

      virtual size_t max_input_bits() const override
         {
         return m_pub_key.max_input_bits();
         }

      virtual size_t message_part_size() const override
         {
         return m_pub_key.message_part_size();
         }

      virtual size_t message_parts() const override
         {
         return m_pub_key.message_parts();
         }

      virtual bool is_valid_signature(const byte sig[],
                                      size_t sig_len) override;

      void update(const byte msg[], size_t msg_len) override;

   private:
      XMSS_WOTS_Addressed_PublicKey m_pub_key;
      secure_vector<byte> m_msg_buf;
   };

}

#endif
