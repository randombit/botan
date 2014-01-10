/*
* OpenSSL Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENGINE_OPENSSL_H__
#define BOTAN_ENGINE_OPENSSL_H__

#include <botan/engine.h>

namespace Botan {

/**
* OpenSSL Engine
*/
class OpenSSL_Engine : public Engine
   {
   public:
      std::string provider_name() const override { return "openssl"; }

      PK_Ops::Key_Agreement*
         get_key_agreement_op(const Private_Key& key, RandomNumberGenerator& rng) const override;

      PK_Ops::Signature*
         get_signature_op(const Private_Key& key, RandomNumberGenerator& rng) const override;

      PK_Ops::Verification* get_verify_op(const Public_Key& key, RandomNumberGenerator& rng) const override;

      PK_Ops::Encryption* get_encryption_op(const Public_Key& key, RandomNumberGenerator& rng) const override;

      PK_Ops::Decryption* get_decryption_op(const Private_Key& key, RandomNumberGenerator& rng) const override;

      Modular_Exponentiator* mod_exp(const BigInt&,
                                     Power_Mod::Usage_Hints) const override;

      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const override;

      StreamCipher* find_stream_cipher(const SCAN_Name&,
                                       Algorithm_Factory&) const override;

      HashFunction* find_hash(const SCAN_Name&, Algorithm_Factory&) const override;
   };

}

#endif
