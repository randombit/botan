/*
* Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENGINE_H__
#define BOTAN_ENGINE_H__

#include <botan/scan_name.h>

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pow_mod.h>
#include <botan/pk_keys.h>
#include <botan/pk_ops.h>

#include <utility>
#include <map>

namespace Botan {

class Algorithm_Factory;
class Keyed_Filter;

/*
* Engine Base Class
*/
class BOTAN_DLL Engine
   {
   public:
      virtual ~Engine() {}

      virtual std::string provider_name() const = 0;

      // Lookup functions
      virtual BlockCipher*
         find_block_cipher(const SCAN_Name&, Algorithm_Factory&) const
         { return 0; }

      virtual StreamCipher*
         find_stream_cipher(const SCAN_Name&, Algorithm_Factory&) const
         { return 0; }

      virtual HashFunction*
         find_hash(const SCAN_Name&, Algorithm_Factory&) const
         { return 0; }

      virtual MessageAuthenticationCode*
         find_mac(const SCAN_Name&, Algorithm_Factory&) const
         { return 0; }

      virtual Modular_Exponentiator*
         mod_exp(const BigInt&, Power_Mod::Usage_Hints) const
         { return 0; }

      virtual Keyed_Filter* get_cipher(const std::string&,
                                       Cipher_Dir,
                                       Algorithm_Factory&)
         { return 0; }

      virtual PK_Ops::Key_Agreement*
         get_key_agreement_op(const Private_Key&) const
         {
         return 0;
         }

      virtual PK_Ops::Signature* get_signature_op(const Private_Key&) const
         {
         return 0;
         }

      virtual PK_Ops::Verification* get_verify_op(const Public_Key&) const
         {
         return 0;
         }

      virtual PK_Ops::Encryption* get_encryption_op(const Public_Key&) const
         {
         return 0;
         }

      virtual PK_Ops::Decryption* get_decryption_op(const Private_Key&) const
         {
         return 0;
         }
   };

}

#endif
