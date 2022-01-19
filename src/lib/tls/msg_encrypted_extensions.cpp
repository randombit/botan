/*
* TLS Hello Request and Client Hello Messages
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Hannes Rantzsch
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/build.h>
#if defined(BOTAN_HAS_TLS_13)

#include <botan/tls_messages.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Encrypted_Extensions::Encrypted_Extensions(const std::vector<uint8_t>& buf)
{
TLS_Data_Reader reader("encrypted extensions reader", buf);
m_extensions.deserialize(reader, Connection_Side::SERVER);
}

}

#endif
