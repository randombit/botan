/**
* MDx Hash Function
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MDX_BASE_H__
#define BOTAN_MDX_BASE_H__

#include <botan/hash.h>

namespace Botan {

/**
* MDx Hash Function Base Class
*/
class BOTAN_DLL MDx_HashFunction : public HashFunction
   {
   public:
      MDx_HashFunction(u32bit, u32bit, bool, bool, u32bit = 8);
      virtual ~MDx_HashFunction() {}
   protected:
      void add_data(const byte[], u32bit);
      void final_result(byte output[]);
      virtual void compress_n(const byte block[], u32bit block_n) = 0;

      void clear() throw();
      virtual void copy_out(byte[]) = 0;
      virtual void write_count(byte[]);
   private:
      SecureVector<byte> buffer;
      u64bit count;
      u32bit position;

      const bool BIG_BYTE_ENDIAN, BIG_BIT_ENDIAN;
      const u32bit COUNT_SIZE;
   };

}

#endif
