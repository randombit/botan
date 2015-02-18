/*
* ANSI X9.19 MAC
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ANSI_X919_MAC_H__
#define BOTAN_ANSI_X919_MAC_H__

#include <botan/mac.h>
#include <botan/block_cipher.h>

namespace Botan {

/**
* DES/3DES-based MAC from ANSI X9.19
*/
class BOTAN_DLL ANSI_X919_MAC : public MessageAuthenticationCode
   {
   public:
      void clear();
      std::string name() const;
      size_t output_length() const { return 8; }

      MessageAuthenticationCode* clone() const;

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(8, 16, 8);
         }

      ANSI_X919_MAC();

      ANSI_X919_MAC(const ANSI_X919_MAC&) = delete;
      ANSI_X919_MAC& operator=(const ANSI_X919_MAC&) = delete;
   private:
      void add_data(const byte[], size_t);
      void final_result(byte[]);
      void key_schedule(const byte[], size_t);

      std::unique_ptr<BlockCipher> m_des1, m_des2;
      secure_vector<byte> m_state;
      size_t m_position;
   };

}

#endif
