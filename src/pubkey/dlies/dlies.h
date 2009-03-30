/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DLIES_H__
#define BOTAN_DLIES_H__

#include <botan/pubkey.h>
#include <botan/mac.h>
#include <botan/kdf.h>

namespace Botan {

/*
* DLIES Encryption
*/
class BOTAN_DLL DLIES_Encryptor : public PK_Encryptor
   {
   public:
      DLIES_Encryptor(const PK_Key_Agreement_Key&,
                      KDF* kdf,
                      MessageAuthenticationCode* mac,
                      u32bit mac_key_len = 20);

      ~DLIES_Encryptor();

      void set_other_key(const MemoryRegion<byte>&);
   private:
      SecureVector<byte> enc(const byte[], u32bit,
                             RandomNumberGenerator&) const;
      u32bit maximum_input_size() const;

      const PK_Key_Agreement_Key& key;
      SecureVector<byte> other_key;

      KDF* kdf;
      MessageAuthenticationCode* mac;
      u32bit mac_keylen;
   };

/*
* DLIES Decryption
*/
class BOTAN_DLL DLIES_Decryptor : public PK_Decryptor
   {
   public:
      DLIES_Decryptor(const PK_Key_Agreement_Key&,
                      KDF* kdf,
                      MessageAuthenticationCode* mac,
                      u32bit mac_key_len = 20);

      ~DLIES_Decryptor();

   private:
      SecureVector<byte> dec(const byte[], u32bit) const;

      const PK_Key_Agreement_Key& key;

      KDF* kdf;
      MessageAuthenticationCode* mac;
      u32bit mac_keylen;
   };

}

#endif
