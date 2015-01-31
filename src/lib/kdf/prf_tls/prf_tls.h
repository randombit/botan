/*
* TLS v1.0 and v1.2 PRFs
* (C) 2004-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_PRF_H__
#define BOTAN_TLS_PRF_H__

#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
* PRF used in TLS 1.0/1.1
*/
class BOTAN_DLL TLS_PRF : public KDF
   {
   public:
      secure_vector<byte> derive(size_t key_len,
                                const byte secret[], size_t secret_len,
                                const byte seed[], size_t seed_len) const;

      std::string name() const { return "TLS-PRF"; }
      KDF* clone() const { return new TLS_PRF; }

      TLS_PRF();
   private:
      std::unique_ptr<MessageAuthenticationCode> hmac_md5;
      std::unique_ptr<MessageAuthenticationCode> hmac_sha1;
   };

/**
* PRF used in TLS 1.2
*/
class BOTAN_DLL TLS_12_PRF : public KDF
   {
   public:
      secure_vector<byte> derive(size_t key_len,
                                const byte secret[], size_t secret_len,
                                const byte seed[], size_t seed_len) const;

      std::string name() const { return "TLS-12-PRF(" + m_mac->name() + ")"; }
      KDF* clone() const { return new TLS_12_PRF(m_mac->clone()); }

      TLS_12_PRF(MessageAuthenticationCode* mac);

      static TLS_12_PRF* make(const Spec& spec);
   private:
      std::unique_ptr<MessageAuthenticationCode> m_mac;
   };

}

#endif
