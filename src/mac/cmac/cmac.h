/*
* CMAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CMAC_H__
#define BOTAN_CMAC_H__

#include <botan/mac.h>
#include <botan/block_cipher.h>

namespace Botan {

/**
* CMAC, also known as OMAC1
*/
class BOTAN_DLL CMAC : public MessageAuthenticationCode
   {
   public:
      void clear();
      std::string name() const;
      MessageAuthenticationCode* clone() const;

      /**
      * CMAC's polynomial doubling operation
      * @param in the input
      * @param polynomial the byte value of the polynomial
      */
      static SecureVector<byte> poly_double(const MemoryRegion<byte>& in,
                                            byte polynomial);

      /**
      * @param cipher the underlying block cipher to use
      */
      CMAC(BlockCipher* cipher);
      ~CMAC();
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key_schedule(const byte[], u32bit);

      BlockCipher* e;
      SecureVector<byte> buffer, state, B, P;
      u32bit position;
      byte polynomial;
   };

}

#endif
