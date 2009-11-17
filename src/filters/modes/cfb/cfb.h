/*
* CFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CFB_H__
#define BOTAN_CFB_H__

#include <botan/modebase.h>

namespace Botan {

/*
* CFB Encryption
*/
class BOTAN_DLL CFB_Encryption : public BlockCipherMode
   {
   public:
      CFB_Encryption(BlockCipher*, u32bit = 0);
      CFB_Encryption(BlockCipher*, const SymmetricKey&,
                     const InitializationVector&, u32bit = 0);
   private:
      void write(const byte[], u32bit);
      void feedback();
      const u32bit FEEDBACK_SIZE;
   };

/*
* CFB Decryption
*/
class BOTAN_DLL CFB_Decryption : public BlockCipherMode
   {
   public:
      CFB_Decryption(BlockCipher*, u32bit = 0);
      CFB_Decryption(BlockCipher*, const SymmetricKey&,
                     const InitializationVector&, u32bit = 0);
   private:
      void write(const byte[], u32bit);
      void feedback();
      const u32bit FEEDBACK_SIZE;
   };

}

#endif
