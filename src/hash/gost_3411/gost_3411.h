/**
* GOST 34.11
* (C) 2009 Jack Lloyd
*/

#ifndef BOTAN_GOST_3411_H__
#define BOTAN_GOST_3411_H__

#include <botan/hash.h>
#include <botan/gost_28147.h>

namespace Botan {

/**
* GOST 34.11
*/
class BOTAN_DLL GOST_34_11 : public HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "GOST-R-34.11-94" ; }
      HashFunction* clone() const { return new GOST_34_11; }

      GOST_34_11();
   protected:
      void compress_n(const byte input[], u32bit blocks);

      void add_data(const byte[], u32bit);
      void final_result(byte[]);

      GOST_28147_89 cipher;
      SecureBuffer<byte, 32> buffer;
      SecureBuffer<byte, 32> sum;
      SecureBuffer<byte, 32> hash;
      u64bit count;
      u32bit position;
   };

}

#endif
