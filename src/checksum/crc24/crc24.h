/*
* CRC24
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CRC24_H__
#define BOTAN_CRC24_H__

#include <botan/hash.h>

namespace Botan {

/*
* CRC24
*/
class BOTAN_DLL CRC24 : public HashFunction
   {
   public:
      void clear() throw() { crc = 0xB704CE; }
      std::string name() const { return "CRC24"; }
      HashFunction* clone() const { return new CRC24; }
      CRC24() : HashFunction(3) { clear(); }
      ~CRC24() { clear(); }
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      u32bit crc;
   };

}

#endif
