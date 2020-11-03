/*
 * XMSS WOTS Public Key
 * A Winternitz One Time Signature public key for use with Extended Hash-Based
 * Signatures.
 *
 * (C) 2016,2017,2018 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss_wots.h>
#include <botan/internal/xmss_address.h>

namespace Botan {

void
XMSS_WOTS_PublicKey::chain(secure_vector<uint8_t>& result,
                           size_t start_idx,
                           size_t steps,
                           XMSS_Address& adrs,
                           const secure_vector<uint8_t>& seed,
                           XMSS_Hash& hash)
   {
   secure_vector<uint8_t> prf_output(hash.output_length());

   for(size_t i = start_idx;
         i < (start_idx + steps) && i < m_wots_params.wots_parameter();
         i++)
      {
      adrs.set_hash_address(static_cast<uint32_t>(i));

      //Calculate tmp XOR bitmask
      adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_Mode);
      hash.prf(prf_output, seed, adrs.bytes());
      xor_buf(result, prf_output, result.size());

      // Calculate key
      adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);

      //Calculate f(key, tmp XOR bitmask)
      hash.prf(prf_output, seed, adrs.bytes());
      hash.f(result, prf_output, result);
      }
   }

wots_keysig_t
XMSS_WOTS_PublicKey::pub_key_from_signature(const secure_vector<uint8_t>& msg,
                                            const wots_keysig_t& sig,
                                            XMSS_Address& adrs,
                                            const secure_vector<uint8_t>& seed)
   {
   secure_vector<uint8_t> msg_digest
      {
      m_wots_params.base_w(msg, m_wots_params.len_1())
      };

   m_wots_params.append_checksum(msg_digest);
   wots_keysig_t result(sig);

   for(size_t i = 0; i < m_wots_params.len(); i++)
      {
      adrs.set_chain_address(static_cast<uint32_t>(i));
      chain(result[i],
            msg_digest[i],
            m_wots_params.wots_parameter() - 1 - msg_digest[i],
            adrs,
            seed);
      }
   return result;
   }

}
