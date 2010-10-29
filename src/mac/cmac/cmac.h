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
      std::string name() const;
      size_t output_length() const { return e->block_size(); }
      MessageAuthenticationCode* clone() const;

      void clear();

      Key_Length_Specification key_spec() const
         {
         return e->key_spec();
         }

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
      void add_data(const byte[], size_t);
      void final_result(byte[]);
      void key_schedule(const byte[], size_t);

      BlockCipher* e;
      SecureVector<byte> buffer, state, B, P;
      size_t position;
      byte polynomial;
   };

}

#endif
