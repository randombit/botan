/*
 * XMSS WOTS Public Key
 * A Winternitz One Time Signature public key for use with Extended Hash-Based
 * Signatures.
 *
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_wots_verification_operation.h>
#include <botan/xmss_wots_publickey.h>

namespace Botan {

void
XMSS_WOTS_PublicKey::chain(secure_vector<byte>& result,
                           size_t start_idx,
                           size_t steps,
                           XMSS_Address& adrs,
                           const secure_vector<byte>& seed)
   {
   for(size_t i = start_idx;
         i < (start_idx + steps) && i < m_wots_params.wots_parameter();
         i++)
      {
      adrs.set_hash_address(i);

      //Calculate tmp XOR bitmask
      adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_Mode);
      xor_buf(result, m_hash.prf(seed, adrs.bytes()), result.size());

      // Calculate key
      adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);

      //Calculate f(key, tmp XOR bitmask)
      m_hash.f(result, m_hash.prf(seed, adrs.bytes()), result);
      }
   }

wots_keysig_t
XMSS_WOTS_PublicKey::pub_key_from_signature(const secure_vector<byte>& msg,
      const wots_keysig_t& sig,
      XMSS_Address& adrs,
      const secure_vector<byte>& seed)
   {
   secure_vector<byte> msg_digest
      {
      m_wots_params.base_w(msg, m_wots_params.len_1())
      };

   m_wots_params.append_checksum(msg_digest);
   wots_keysig_t result(sig);

   for(size_t i = 0; i < m_wots_params.len(); i++)
      {
      adrs.set_chain_address(i);
      chain(result[i],
            msg_digest[i],
            m_wots_params.wots_parameter() - 1 - msg_digest[i],
            adrs,
            seed);
      }
   return result;
   }

std::unique_ptr<PK_Ops::Verification>
XMSS_WOTS_PublicKey::create_verification_op(const std::string&,
                                            const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      return std::unique_ptr<PK_Ops::Verification>(
         new XMSS_WOTS_Verification_Operation(*this));
      }
   throw Provider_Not_Found(algo_name(), provider);
   }

}
