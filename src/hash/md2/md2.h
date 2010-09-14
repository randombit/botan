/*
* MD2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MD2_H__
#define BOTAN_MD2_H__

#include <botan/hash.h>

namespace Botan {

/**
* MD2
*/
class BOTAN_DLL MD2 : public HashFunction
   {
   public:
      void clear();
      std::string name() const { return "MD2"; }
      HashFunction* clone() const { return new MD2; }

      MD2() : HashFunction(16, 16), X(48), checksum(16), buffer(16)
         { clear(); }
   private:
      void add_data(const byte[], u32bit);
      void hash(const byte[]);
      void final_result(byte[]);

      SecureVector<byte> X, checksum, buffer;
      u32bit position;
   };

}

#endif
