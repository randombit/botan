/*
* ANSI X9.19 MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
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
      void clear() throw();
      std::string name() const;
      MessageAuthenticationCode* clone() const;

      ANSI_X919_MAC(BlockCipher*);
      ~ANSI_X919_MAC();
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key_schedule(const byte[], u32bit);

      BlockCipher* e;
      BlockCipher* d;
      SecureBuffer<byte, 8> state;
      u32bit position;
   };

}

#endif
