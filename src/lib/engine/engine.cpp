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

}
