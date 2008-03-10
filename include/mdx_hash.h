/*************************************************
* MDx Hash Function Header File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_MDX_BASE_H__
#define BOTAN_MDX_BASE_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* MDx Hash Function Base Class                   *
*************************************************/
class MDx_HashFunction : public HashFunction
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

      virtual void hash(const byte[]) = 0;
      virtual void copy_out(byte[]) = 0;
      virtual void write_count(byte[]);

      const bool BIG_BYTE_ENDIAN, BIG_BIT_ENDIAN;
      const u32bit COUNT_SIZE;
   };

}

#endif
