/*
* TLS Certificate Request Message - implementation for TLS 1.2
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CERT_REQ_IMPL_12_H_
#define BOTAN_MSG_CERT_REQ_IMPL_12_H_

#include <botan/x509cert.h>
#include <botan/internal/msg_cert_req_impl.h>

#include <vector>
#include <string>

namespace Botan {

namespace TLS {

class Handshake_IO;
class Handshake_Hash;
class Policy;

/**
* Certificate Request Message TLSv1.2 implementation
*/
class Certificate_Req_Impl_12 final : public Certificate_Req_Impl
   {
   public:
      const std::vector<std::string>& acceptable_cert_types() const override;

      const std::vector<X509_DN>& acceptable_CAs() const override;

      const std::vector<Signature_Scheme>& signature_schemes() const override;

      explicit Certificate_Req_Impl_12(Handshake_IO& io,
                                       Handshake_Hash& hash,
                                       const Policy& policy,
                                       const std::vector<X509_DN>& allowed_cas);

      explicit Certificate_Req_Impl_12(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;

   private:
      std::vector<X509_DN> m_names;
      std::vector<std::string> m_cert_key_types;
      std::vector<Signature_Scheme> m_schemes;
   };
}

}

#endif
