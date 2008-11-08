/*************************************************
* OFB Mode Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_OUTPUT_FEEDBACK_MODE_H__
#define BOTAN_OUTPUT_FEEDBACK_MODE_H__

#include <botan/modebase.h>
#include <botan/block_cipher.h>

namespace Botan {

/*************************************************
* OFB Mode                                       *
*************************************************/
class BOTAN_DLL OFB : public BlockCipherMode
   {
   public:
      OFB(BlockCipher* cipher);

      OFB(BlockCipher* cipher,
          const SymmetricKey& key,
          const InitializationVector& iv);
   private:
      void write(const byte[], u32bit);
   };

}

#endif
