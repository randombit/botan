/*************************************************
* Block Cipher Mode Header File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_MODEBASE_H__
#define BOTAN_MODEBASE_H__

#include <botan/basefilt.h>

namespace Botan {

/*************************************************
* Block Cipher Mode                              *
*************************************************/
class BlockCipherMode : public Keyed_Filter
   {
   public:
      std::string name() const;

      BlockCipherMode(const std::string&, const std::string&,
                      u32bit, u32bit = 0, u32bit = 1);
      virtual ~BlockCipherMode() { delete cipher; }
   protected:
      void set_iv(const InitializationVector&);
      const u32bit BLOCK_SIZE, BUFFER_SIZE, IV_METHOD;
      const std::string mode_name;
      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      u32bit position;
   };

}

#endif
