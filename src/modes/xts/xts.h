/*
* XTS mode, from IEEE P1619
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_XTS_H__
#define BOTAN_XTS_H__

#include <botan/basefilt.h>
#include <botan/block_cipher.h>

namespace Botan {

/*
* XTS Encryption
*/
class BOTAN_DLL XTS_Encryption : public Keyed_Filter
   {
   public:
      void set_key(const SymmetricKey& key);
      void set_iv(const InitializationVector& iv);

      std::string name() const;

      XTS_Encryption(BlockCipher* ciph);

      XTS_Encryption(BlockCipher* ciph,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~XTS_Encryption() { delete cipher; delete cipher2; }
   private:
      void write(const byte[], u32bit);
      void end_msg();
      void encrypt(const byte block[]);

      BlockCipher* cipher;
      BlockCipher* cipher2;
      SecureVector<byte> tweak;
      SecureVector<byte> buffer;
      u32bit position;
   };

/*
* XTS Decryption
*/
class BOTAN_DLL XTS_Decryption : public Keyed_Filter
   {
   public:
      void set_key(const SymmetricKey& key);
      void set_iv(const InitializationVector& iv);

      std::string name() const;

      XTS_Decryption(BlockCipher* ciph);

      XTS_Decryption(BlockCipher* ciph,
                     const SymmetricKey& key,
                     const InitializationVector& iv);
   private:
      void write(const byte[], u32bit);
      void end_msg();
      void decrypt(const byte[]);

      BlockCipher* cipher;
      BlockCipher* cipher2;
      SecureVector<byte> tweak;
      SecureVector<byte> buffer;
      u32bit position;
   };

}

#endif
