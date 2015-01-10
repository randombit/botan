/*
* Engine
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/engine.h>

namespace Botan {

BlockCipher*
Engine::find_block_cipher(const SCAN_Name&,
                          Algorithm_Factory&) const
   {
   return nullptr;
   }

StreamCipher*
Engine::find_stream_cipher(const SCAN_Name&,
                           Algorithm_Factory&) const
   {
   return nullptr;
   }

HashFunction*
Engine::find_hash(const SCAN_Name&,
                  Algorithm_Factory&) const
   {
   return nullptr;
   }

MessageAuthenticationCode*
Engine::find_mac(const SCAN_Name&,
                 Algorithm_Factory&) const
   {
   return nullptr;
   }

PBKDF*
Engine::find_pbkdf(const SCAN_Name&,
                   Algorithm_Factory&) const
   {
   return nullptr;
   }

Modular_Exponentiator*
Engine::mod_exp(const BigInt&,
                Power_Mod::Usage_Hints) const
   {
   return nullptr;
   }

Keyed_Filter* Engine::get_cipher(const std::string&,
                                 Cipher_Dir,
                                 Algorithm_Factory&)
   {
   return nullptr;
   }

PK_Ops::Key_Agreement*
Engine::get_key_agreement_op(const Private_Key&, RandomNumberGenerator&) const
   {
   return nullptr;
   }

PK_Ops::Signature*
Engine::get_signature_op(const Private_Key&, const std::string&, RandomNumberGenerator&) const
   {
   return nullptr;
   }

PK_Ops::Verification*
Engine::get_verify_op(const Public_Key&, const std::string&, RandomNumberGenerator&) const
   {
   return nullptr;
   }

PK_Ops::Encryption*
Engine::get_encryption_op(const Public_Key&, RandomNumberGenerator&) const
   {
   return nullptr;
   }

PK_Ops::Decryption*
Engine::get_decryption_op(const Private_Key&, RandomNumberGenerator&) const
   {
   return nullptr;
   }

}
