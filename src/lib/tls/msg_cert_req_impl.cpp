/*
* Certificate Request Message
* (C) 2004-2006,2012 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/msg_cert_req_impl.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

namespace TLS {

Certificate_Req_Impl::Certificate_Req_Impl() = default;

Handshake_Type Certificate_Req_Impl::type() const
   {
   return CERTIFICATE_REQUEST;
   }

}

}
