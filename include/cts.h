/*************************************************
* CTS Mode Header File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_CTS_H__
#define BOTAN_CTS_H__

#include <botan/modebase.h>

namespace Botan {

/*************************************************
* CTS Encryption                                 *
*************************************************/
class CTS_Encryption : public BlockCipherMode
   {
   public:
      CTS_Encryption(const std::string&);
      CTS_Encryption(const std::string&,
                     const SymmetricKey&, const InitializationVector&);
   private:
      void write(const byte[], u32bit);
      void end_msg();
      void encrypt(const byte[]);
   };

/*************************************************
* CTS Decryption                                 *
*************************************************/
class CTS_Decryption : public BlockCipherMode
   {
   public:
      CTS_Decryption(const std::string&);
      CTS_Decryption(const std::string&,
                     const SymmetricKey&, const InitializationVector&);
   private:
      void write(const byte[], u32bit);
      void end_msg();
      void decrypt(const byte[]);
      SecureVector<byte> temp;
   };

}

#endif
