/*
* CTS Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CTS_H__
#define BOTAN_CTS_H__

#include <botan/block_cipher.h>
#include <botan/key_filt.h>

namespace Botan {

/*
* CTS Encryption
*/
class BOTAN_DLL CTS_Encryption : public Keyed_Filter
   {
   public:
      std::string name() const { return cipher->name() + "/CTS"; }

      void set_iv(const InitializationVector&);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(u32bit key_len) const
         { return cipher->valid_keylength(key_len); }

      CTS_Encryption(BlockCipher* cipher);

      CTS_Encryption(BlockCipher* cipher,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~CTS_Encryption() { delete cipher; }
   private:
      void write(const byte[], u32bit);
      void end_msg();
      void encrypt(const byte[]);

      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      u32bit position;
   };

/*
* CTS Decryption
*/
class BOTAN_DLL CTS_Decryption : public Keyed_Filter
   {
   public:
      std::string name() const { return cipher->name() + "/CTS"; }

      void set_iv(const InitializationVector&);

      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      bool valid_keylength(u32bit key_len) const
         { return cipher->valid_keylength(key_len); }

      CTS_Decryption(BlockCipher* cipher);

      CTS_Decryption(BlockCipher* cipher,
                     const SymmetricKey& key,
                     const InitializationVector& iv);

      ~CTS_Decryption() { delete cipher; }
   private:
      void write(const byte[], u32bit);
      void end_msg();
      void decrypt(const byte[]);

      BlockCipher* cipher;
      SecureVector<byte> buffer, state, temp;
      u32bit position;
   };

}

#endif
