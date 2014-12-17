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

      BlockCipher* find_block_cipher(const SCAN_Name&,
                                     Algorithm_Factory&) const override;

      StreamCipher* find_stream_cipher(const SCAN_Name&,
                                       Algorithm_Factory&) const override;

      HashFunction* find_hash(const SCAN_Name&, Algorithm_Factory&) const override;
   };

}

#endif
