/*************************************************
* OFB Mode Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_OFB_H__
#define BOTAN_OFB_H__

#include <botan/modebase.h>

namespace Botan {

/*************************************************
* OFB Mode                                       *
*************************************************/
class BOTAN_DLL OFB : public BlockCipherMode
   {
   public:
      OFB(const std::string&);
      OFB(const std::string&,
          const SymmetricKey&, const InitializationVector&);
   private:
      void write(const byte[], u32bit);
   };

}

#endif
