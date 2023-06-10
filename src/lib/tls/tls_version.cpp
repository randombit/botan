/*
* TLS Protocol Version Management
* (C) 2012 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_version.h>

#include <botan/tls_exceptn.h>

namespace Botan::TLS {

std::string Protocol_Version::to_string() const {
   const uint8_t maj = major_version();
   const uint8_t min = minor_version();

   if(maj == 3 && min == 0) {
      return "SSL v3";
   }

   if(maj == 3 && min >= 1) {  // TLS v1.x
      return "TLS v1." + std::to_string(min - 1);
   }

   if(maj == 254) {  // DTLS 1.x
      return "DTLS v1." + std::to_string(255 - min);
   }

   // Some very new or very old protocol (or bogus data)
   return "Unknown " + std::to_string(maj) + "." + std::to_string(min);
}

bool Protocol_Version::is_datagram_protocol() const {
   return major_version() > 250;
}

bool Protocol_Version::is_pre_tls_13() const {
   return (!is_datagram_protocol() && *this <= Protocol_Version::TLS_V12) ||
          (is_datagram_protocol() && *this <= Protocol_Version::DTLS_V12);
}

bool Protocol_Version::is_tls_13_or_later() const {
   return (!is_datagram_protocol() && *this >= Protocol_Version::TLS_V13) ||
          (is_datagram_protocol() && *this >= Protocol_Version::DTLS_V13);
}

bool Protocol_Version::operator>(const Protocol_Version& other) const {
   if(this->is_datagram_protocol() != other.is_datagram_protocol()) {
      throw TLS_Exception(Alert::ProtocolVersion, "Version comparing " + to_string() + " with " + other.to_string());
   }

   if(this->is_datagram_protocol()) {
      return m_version < other.m_version;  // goes backwards
   }

   return m_version > other.m_version;
}

bool Protocol_Version::valid() const {
   const uint8_t maj = major_version();
   const uint8_t min = minor_version();

   if(maj == 3 && min <= 4) {
      // 3.0: SSLv3
      // 3.1: TLS 1.0
      // 3.2: TLS 1.1
      // 3.3: TLS 1.2
      // 3.4: TLS 1.3
      return true;
   }

   if(maj == 254 && (min == 253 || min == 255)) {
      // 254.253: DTLS 1.2
      // 254.255: DTLS 1.0
      return true;
   }

   return false;
}

bool Protocol_Version::known_version() const {
   return (m_version == static_cast<uint16_t>(Protocol_Version::TLS_V12) ||
#if defined(BOTAN_HAS_TLS_13)
           m_version == static_cast<uint16_t>(Protocol_Version::TLS_V13) ||
#endif
           m_version == static_cast<uint16_t>(Protocol_Version::DTLS_V12));
}

}  // namespace Botan::TLS
