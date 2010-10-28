/*
* TLS Session Key
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_SESSION_KEYS_H__
#define BOTAN_TLS_SESSION_KEYS_H__

#include <botan/tls_suites.h>
#include <botan/tls_exceptn.h>
#include <botan/symkey.h>

namespace Botan {

/**
* TLS Session Keys
*/
class BOTAN_DLL SessionKeys
   {
   public:
      SymmetricKey client_cipher_key() const;
      SymmetricKey server_cipher_key() const;

      SymmetricKey client_mac_key() const;
      SymmetricKey server_mac_key() const;

      InitializationVector client_iv() const;
      InitializationVector server_iv() const;

      SecureVector<byte> master_secret() const;

      SessionKeys() {}
      SessionKeys(const CipherSuite&, Version_Code, const MemoryRegion<byte>&,
                  const MemoryRegion<byte>&, const MemoryRegion<byte>&);
   private:
      SymmetricKey ssl3_keygen(size_t, const MemoryRegion<byte>&,
                               const MemoryRegion<byte>&,
                               const MemoryRegion<byte>&);
      SymmetricKey tls1_keygen(size_t, const MemoryRegion<byte>&,
                               const MemoryRegion<byte>&,
                               const MemoryRegion<byte>&);

      SecureVector<byte> master_sec;
      SymmetricKey c_cipher, s_cipher, c_mac, s_mac;
      InitializationVector c_iv, s_iv;
   };

}

#endif
