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
      void compress_n(const byte input[], size_t blocks);

      void add_data(const byte[], size_t);
      void final_result(byte[]);

      GOST_28147_89 cipher;
      SecureVector<byte> buffer, sum, hash;
      size_t position;
      u64bit count;
   };

}

#endif
