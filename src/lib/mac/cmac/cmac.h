/*
* CMAC
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CMAC_H__
#define BOTAN_CMAC_H__

#include <botan/mac.h>
#include <botan/block_cipher.h>

namespace Botan {

/**
* CMAC, also known as OMAC1
*/
class BOTAN_DLL CMAC final : public MessageAuthenticationCode
   {
   public:
      std::string name() const override;
      size_t output_length() const override { return m_cipher->block_size(); }
      MessageAuthenticationCode* clone() const override;

      void clear() override;

      Key_Length_Specification key_spec() const override
         {
         return m_cipher->key_spec();
         }

      /**
      * CMAC's polynomial doubling operation
      * @param in the input
      * @param polynomial the byte value of the polynomial
      */
      static secure_vector<byte> poly_double(const secure_vector<byte>& in);

      /**
      * @param cipher the underlying block cipher to use
      */
      explicit CMAC(BlockCipher* cipher);

      static CMAC* make(const Spec& spec);

      CMAC(const CMAC&) = delete;
      CMAC& operator=(const CMAC&) = delete;
   private:
      void add_data(const byte[], size_t) override;
      void final_result(byte[]) override;
      void key_schedule(const byte[], size_t) override;

      std::unique_ptr<BlockCipher> m_cipher;
      secure_vector<byte> m_buffer, m_state, m_B, m_P;
      size_t m_position;
   };

}

#endif
