/*
* Engine
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/engine.h>

namespace Botan {

BlockCipher*
Engine::find_block_cipher(const SCAN_Name&,
                          Algorithm_Factory&) const
   {
   return 0;
   }

StreamCipher*
Engine::find_stream_cipher(const SCAN_Name&,
                           Algorithm_Factory&) const
   {
   return 0;
   }

HashFunction*
Engine::find_hash(const SCAN_Name&,
                  Algorithm_Factory&) const
   {
   return 0;
   }

MessageAuthenticationCode*
Engine::find_mac(const SCAN_Name&,
                 Algorithm_Factory&) const
   {
   return 0;
   }

PBKDF*
Engine::find_pbkdf(const SCAN_Name&,
                   Algorithm_Factory&) const
   {
   return 0;
   }

Modular_Exponentiator*
Engine::mod_exp(const BigInt&,
                Power_Mod::Usage_Hints) const
   {
   return 0;
   }

Keyed_Filter* Engine::get_cipher(const std::string&,
                                 Cipher_Dir,
                                 Algorithm_Factory&)
   {
   return 0;
   }

PK_Ops::Key_Agreement*
Engine::get_key_agreement_op(const Private_Key&) const
   {
   return 0;
   }

PK_Ops::Signature*
Engine::get_signature_op(const Private_Key&) const
   {
   return 0;
   }

PK_Ops::Verification*
Engine::get_verify_op(const Public_Key&) const
   {
   return 0;
   }

PK_Ops::Encryption*
Engine::get_encryption_op(const Public_Key&) const
   {
   return 0;
   }

PK_Ops::Decryption*
Engine::get_decryption_op(const Private_Key&) const
   {
   return 0;
   }

}
