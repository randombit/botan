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
      SymmetricKey client_cipher_key() const { return c_cipher; }
      SymmetricKey server_cipher_key() const { return s_cipher; }

      SymmetricKey client_mac_key() const { return c_mac; }
      SymmetricKey server_mac_key() const { return s_mac; }

      InitializationVector client_iv() const { return c_iv; }
      InitializationVector server_iv() const { return s_iv; }

      SecureVector<byte> master_secret() const { return master_sec; }

      SessionKeys() {}

      SessionKeys(const CipherSuite& suite,
                  Version_Code version,
                  const MemoryRegion<byte>& pre_master,
                  const MemoryRegion<byte>& client_random,
                  const MemoryRegion<byte>& server_random,
                  bool resuming = false);

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
