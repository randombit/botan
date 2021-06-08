/*
* TLS Certificate Message - implementation for TLS 1.2
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CERTIFICATE_IMPL_12_H_
#define BOTAN_MSG_CERTIFICATE_IMPL_12_H_

#include <botan/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <botan/tls_session.h>
#include <botan/tls_policy.h>
#include <botan/tls_ciphersuite.h>
#include <botan/pk_keys.h>
#include <botan/x509cert.h>
#include <botan/ocsp.h>
#include <botan/internal/msg_certificate_impl.h>
#include <vector>

namespace Botan {

namespace TLS {

class Handshake_IO;

/**
* Certificate Message TLSv1.2 implementation
*/
class Certificate_Impl_12 final : public Certificate_Impl
   {
   public:
      const std::vector<X509_Certificate>& cert_chain() const override;

      size_t count() const override;
      bool empty() const override;

      explicit Certificate_Impl_12(Handshake_IO& io,
                                   Handshake_Hash& hash,
                                   const std::vector<X509_Certificate>& certs);

      explicit Certificate_Impl_12(const std::vector<uint8_t>& buf, const Policy &policy);

      std::vector<uint8_t> serialize() const override;

   private:
      std::vector<X509_Certificate> m_certs;
   };

}

}

#endif
