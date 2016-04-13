/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DLIES_H__
#define BOTAN_DLIES_H__

#include <botan/pubkey.h>
#include <botan/mac.h>
#include <botan/kdf.h>

namespace Botan {

/**
* DLIES Encryption
*/
class BOTAN_DLL DLIES_Encryptor : public PK_Encryptor
   {
   public:
      DLIES_Encryptor(const PK_Key_Agreement_Key&,
                      KDF* kdf,
                      MessageAuthenticationCode* mac,
                      size_t mac_key_len = 20);

      void set_other_key(const std::vector<byte>&);
   private:
      std::vector<byte> enc(const byte[], size_t,
                            RandomNumberGenerator&) const override;

      size_t maximum_input_size() const override;

      std::vector<byte> m_other_key, m_my_key;

      PK_Key_Agreement m_ka;
      std::unique_ptr<KDF> m_kdf;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      size_t m_mac_keylen;
   };

/**
* DLIES Decryption
*/
class BOTAN_DLL DLIES_Decryptor : public PK_Decryptor
   {
   public:
      DLIES_Decryptor(const PK_Key_Agreement_Key&,
                      KDF* kdf,
                      MessageAuthenticationCode* mac,
                      size_t mac_key_len = 20);

   private:
      secure_vector<byte> do_decrypt(byte& valid_mask,
                                     const byte in[], size_t in_len) const override;

      std::vector<byte> m_my_key;

      PK_Key_Agreement m_ka;
      std::unique_ptr<KDF> m_kdf;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      size_t m_mac_keylen;
   };

}

#endif
