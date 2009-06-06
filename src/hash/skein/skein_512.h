/**
* The Skein-512 hash function
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SKEIN_512_H__
#define BOTAN_SKEIN_512_H__

#include <botan/secmem.h>
#include <botan/hash.h>
#include <string>

namespace Botan {

class BOTAN_DLL Skein_512 : public HashFunction
   {
   public:
      Skein_512(u32bit output_bits = 512,
                const std::string& personalization = "");

      HashFunction* clone() const;
      std::string name() const;
      void clear() throw();
   private:
      void add_data(const byte input[], u32bit length);
      void final_result(byte out[]);

      std::string personalization;
      u32bit output_bits;
      SecureBuffer<u64bit, 9> H;
      SecureBuffer<u64bit, 3> T;

      SecureBuffer<byte, 64> buffer;
      u32bit buf_pos;
   };

}

#endif
