/*
 * GMAC
 * (C) 2016 Matthias Gierlings, René Korthaus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_GMAC_H__
#define BOTAN_GMAC_H__

#include <botan/types.h>
#include <botan/mac.h>
#include <botan/gcm.h>
#include <algorithm>

namespace Botan {

/**
* GMAC
*/
class BOTAN_DLL GMAC : public MessageAuthenticationCode
   {
   public:
      void clear() override;
      std::string name() const override;
      size_t output_length() const override;
      MessageAuthenticationCode* clone() const override;

      /**
      * Must be called to set the initialization vector prior to GMAC
      * calculation.
      *
      * @param nonce Initialization vector.
      */
      void start(const secure_vector<byte>& nonce);

      /**
      * Must be called to set the initialization vector prior to GMAC
      * calculation.
      *
      * @param nonce Initialization vector.
      */
      void start(const std::vector<byte>& nonce);

      Key_Length_Specification key_spec() const
         {
         return m_gcm.key_spec();
         }

      /**
      * Creates a new GMAC instance.
      *
      * @param cipher the underlying block cipher to use
      */
      explicit GMAC(BlockCipher* cipher);

      static GMAC* make(const Spec& spec);

      GMAC(const GMAC&) = delete;
      GMAC& operator=(const GMAC&) = delete;
   private:
      void add_data(const byte[], size_t) override;
      void final_result(byte[]) override;

      void key_schedule(const byte key[], size_t size) override
        {
        m_gcm.set_key(key, size);
        }

      secure_vector<byte> m_iv;
      secure_vector<byte> m_aad;
      GCM_Encryption m_gcm;
      std::unique_ptr<BlockCipher> m_cipher;
   };

}
#endif
