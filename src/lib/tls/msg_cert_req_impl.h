/*
* TLS Certificate Message interface
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CERT_REQ_IMPL_H_
#define BOTAN_MSG_CERT_REQ_IMPL_H_

#include <botan/tls_handshake_msg.h>
#include <botan/tls_algos.h>
#include <botan/x509cert.h>

#include <vector>
#include <string>

namespace Botan {

namespace TLS {

/**
* Interface of pimpl for Certificate Request Message
*/
class Certificate_Req_Impl : public Handshake_Message
   {
   public:
      Handshake_Type type() const override;

      virtual const std::vector<std::string>& acceptable_cert_types() const = 0;

      virtual const std::vector<X509_DN>& acceptable_CAs() const = 0;

      virtual const std::vector<Signature_Scheme>& signature_schemes() const = 0;

      explicit Certificate_Req_Impl();
   };
}

}

#endif
