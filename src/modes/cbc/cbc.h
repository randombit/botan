/*
* CBC Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CBC_H__
#define BOTAN_CBC_H__

#include <botan/modebase.h>
#include <botan/mode_pad.h>

namespace Botan {

/*
* CBC Encryption
*/
class BOTAN_DLL CBC_Encryption : public BlockCipherMode
   {
   public:
      CBC_Encryption(BlockCipher*, BlockCipherModePaddingMethod*);
      CBC_Encryption(BlockCipher*, BlockCipherModePaddingMethod*,
                     const SymmetricKey&, const InitializationVector&);

      ~CBC_Encryption() { delete padder; }
   private:
      std::string name() const;
      void write(const byte[], u32bit);
      void end_msg();
      const BlockCipherModePaddingMethod* padder;
   };

/*
* CBC Decryption
*/
class BOTAN_DLL CBC_Decryption : public BlockCipherMode
   {
   public:
      CBC_Decryption(BlockCipher*, BlockCipherModePaddingMethod*);
      CBC_Decryption(BlockCipher*, BlockCipherModePaddingMethod*,
                     const SymmetricKey&, const InitializationVector&);

      ~CBC_Decryption() { delete padder; }
   private:
      std::string name() const;
      void write(const byte[], u32bit);
      void end_msg();
      const BlockCipherModePaddingMethod* padder;
      SecureVector<byte> temp;
   };

}

#endif
