/*************************************************
* DLIES Header File                              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_DLIES_H__
#define BOTAN_DLIES_H__

#include <botan/pubkey.h>

namespace Botan {

/*************************************************
* DLIES Encryption                               *
*************************************************/
class DLIES_Encryptor : public PK_Encryptor
   {
   public:
      DLIES_Encryptor(const PK_Key_Agreement_Key&,
                      const std::string& = "KDF2(SHA-160)",
                      const std::string& = "HMAC(SHA-160)", u32bit = 20);
      void set_other_key(const MemoryRegion<byte>&);
   private:
      SecureVector<byte> enc(const byte[], u32bit) const;
      u32bit maximum_input_size() const;
      const PK_Key_Agreement_Key& key;
      SecureVector<byte> other_key;
      const std::string kdf_algo;
      const std::string mac_algo;
      const u32bit MAC_KEYLEN;
   };

/*************************************************
* DLIES Decryption                               *
*************************************************/
class DLIES_Decryptor : public PK_Decryptor
   {
   public:
      DLIES_Decryptor(const PK_Key_Agreement_Key&,
                      const std::string& = "KDF2(SHA-160)",
                      const std::string& = "HMAC(SHA-160)", u32bit = 20);
   private:
      SecureVector<byte> dec(const byte[], u32bit) const;
      const PK_Key_Agreement_Key& key;
      const std::string kdf_algo;
      const std::string mac_algo;
      const u32bit MAC_KEYLEN, PUBLIC_LEN;
   };

}

#endif
