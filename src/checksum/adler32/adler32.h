/*
* Adler32
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ADLER32_H__
#define BOTAN_ADLER32_H__

#include <botan/hash.h>

namespace Botan {

/*
* Adler32
*/
class BOTAN_DLL Adler32 : public HashFunction
   {
   public:
      void clear() throw() { S1 = 1; S2 = 0; }
      std::string name() const { return "Adler32"; }
      HashFunction* clone() const { return new Adler32; }
      Adler32() : HashFunction(4) { clear(); }
      ~Adler32() { clear(); }
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void hash(const byte[], u32bit);
      u16bit S1, S2;
   };

}

#endif
