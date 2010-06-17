/*
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
      /**
      * @param hash_length is the output length of this hash
      * @param block_length is the number of bytes per block
      * @param big_byte_endian specifies if the hash uses big-endian bytes
      * @param big_bit_endian specifies if the hash uses big-endian bits
      * @param counter_size specifies the size of the counter var in bytes
      */
      MDx_HashFunction(u32bit hash_length,
                       u32bit block_length,
                       bool big_byte_endian,
                       bool big_bit_endian,
                       u32bit counter_size = 8);

      virtual ~MDx_HashFunction() {}
   protected:
      void add_data(const byte input[], u32bit length);
      void final_result(byte output[]);

      /**
      * Run the hash's compression function over a set of blocks
      * @param blocks the input
      * @param block_n the number of blocks
      */
      virtual void compress_n(const byte blocks[], u32bit block_n) = 0;

      void clear();

      /**
      * Copy the output to the buffer
      * @param buffer to put the output into
      */
      virtual void copy_out(byte buffer[]) = 0;

      /**
      * Write the count, if used, to this spot
      * @param out where to write the counter to
      */
      virtual void write_count(byte out[]);
   private:
      SecureVector<byte> buffer;
      u64bit count;
      u32bit position;

      const bool BIG_BYTE_ENDIAN, BIG_BIT_ENDIAN;
      const u32bit COUNT_SIZE;
   };

}

#endif
