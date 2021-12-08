/*
* Certificate Message
* (C) 2004-2006,2012,2020 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_certificate_impl.h>
#include <botan/tls_magic.h>

namespace Botan {

namespace TLS {

Handshake_Type Certificate_Impl::type() const
   {
   return CERTIFICATE;
   }

}

}
