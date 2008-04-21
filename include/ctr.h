/*************************************************
* CTR Mode Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_CTR_H__
#define BOTAN_CTR_H__

#include <botan/modebase.h>

namespace Botan {

/*************************************************
* CTR-BE Mode                                    *
*************************************************/
class BOTAN_DLL CTR_BE : public BlockCipherMode
   {
   public:
      CTR_BE(const std::string&);
      CTR_BE(const std::string&,
             const SymmetricKey&, const InitializationVector&);
   private:
      void write(const byte[], u32bit);
      void increment_counter();
   };

}

#endif
