/*************************************************
* CRC32 Header File                              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_CRC32_H__
#define BOTAN_CRC32_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* CRC32                                          *
*************************************************/
class CRC32 : public HashFunction
   {
   public:
      void clear() throw() { crc = 0xFFFFFFFF; }
      std::string name() const { return "CRC32"; }
      HashFunction* clone() const { return new CRC32; }
      CRC32() : HashFunction(4) { clear(); }
      ~CRC32() { clear(); }
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      u32bit crc;
   };

}

#endif
