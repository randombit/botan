/*
* TLS Certificate Message interface
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CERTIFICATE_IMPL_H_
#define BOTAN_MSG_CERTIFICATE_IMPL_H_

#include <botan/tls_handshake_msg.h>
#include <botan/x509cert.h>
#include <vector>

namespace Botan {

namespace TLS {

/**
* Interface of pimpl for Certificate Message
*/
class Certificate_Impl : public Handshake_Message
   {
   public:
      Handshake_Type type() const override;

      virtual const std::vector<X509_Certificate>& cert_chain() const = 0;

      virtual size_t count() const = 0;
      virtual bool empty() const = 0;

      explicit Certificate_Impl() = default;
   };

}

}

#endif
