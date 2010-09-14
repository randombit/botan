/*
* GOST 34.11
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
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
      void clear();
      std::string name() const { return "GOST-R-34.11-94" ; }
      HashFunction* clone() const { return new GOST_34_11; }

      GOST_34_11();
   private:
      void compress_n(const byte input[], u32bit blocks);

      void add_data(const byte[], u32bit);
      void final_result(byte[]);

      GOST_28147_89 cipher;
      SecureVector<byte> buffer, sum, hash;
      u64bit count;
      u32bit position;
   };

}

#endif
