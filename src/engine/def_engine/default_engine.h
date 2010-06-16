/*
* Default Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DEFAULT_ENGINE_H__
#define BOTAN_DEFAULT_ENGINE_H__

#include <botan/engine.h>

namespace Botan {

/**
* Default Engine
*/
class Default_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "core"; }

      PK_Ops::Key_Agreement*
         get_key_agreement_op(const Private_Key& key) const;

      PK_Ops::Signature*
         get_signature_op(const Private_Key& key) const;

      PK_Ops::Verification* get_verify_op(const Public_Key& key) const;

      PK_Ops::Encryption* get_encryption_op(const Public_Key& key) const;

      PK_Ops::Decryption* get_decryption_op(const Private_Key& key) const;

      Modular_Exponentiator* mod_exp(const BigInt& n,
                                     Power_Mod::Usage_Hints) const;

      virtual bool can_add_algorithms() { return true; }

      Keyed_Filter* get_cipher(const std::string&, Cipher_Dir,
                               Algorithm_Factory&);

      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const;

      StreamCipher* find_stream_cipher(const SCAN_Name&,
                                       Algorithm_Factory&) const;

      HashFunction* find_hash(const SCAN_Name& reqeust,
                              Algorithm_Factory&) const;

      MessageAuthenticationCode* find_mac(const SCAN_Name& reqeust,
                                          Algorithm_Factory&) const;
   };

Keyed_Filter* get_cipher_mode(const BlockCipher* block_cipher,
                              Cipher_Dir direction,
                              const std::string& mode,
                              const std::string& padding);

}

#endif
