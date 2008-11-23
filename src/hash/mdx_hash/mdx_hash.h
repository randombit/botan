/**
* MDx Hash Function Header File
* (C) 1999-2008 Jack Lloyd
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
      void clear() throw();
      SecureVector<byte> buffer;
      u64bit count;
      u32bit position;
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte output[]);

      // these are mutually recurisve unless one is overridden
      // (backwards compatability hack)
      virtual void compress_n(const byte block[], u32bit block_n) = 0;
      //virtual void hash(const byte[]);

      virtual void copy_out(byte[]) = 0;
      virtual void write_count(byte[]);

      const bool BIG_BYTE_ENDIAN, BIG_BIT_ENDIAN;
      const u32bit COUNT_SIZE;
   };

}

#endif
