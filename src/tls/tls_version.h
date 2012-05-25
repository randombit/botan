/*
* TLS Protocol Version Management
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_PROTOCOL_VERSION_H__
#define BOTAN_TLS_PROTOCOL_VERSION_H__

#include <botan/get_byte.h>
#include <string>

namespace Botan {

namespace TLS {

class BOTAN_DLL Protocol_Version
   {
   public:
      enum Version_Code {
         SSL_V3             = 0x0300,
         TLS_V10            = 0x0301,
         TLS_V11            = 0x0302,
         TLS_V12            = 0x0303
      };

      Protocol_Version() : m_version(0) {}

      Protocol_Version(Version_Code named_version) :
         m_version(static_cast<u16bit>(named_version)) {}

      Protocol_Version(byte major, byte minor) :
         m_version((static_cast<u16bit>(major) << 8) | minor) {}

      /**
      * Get the major version of the protocol version
      */
      byte major_version() const { return get_byte(0, m_version); }

      /**
      * Get the minor version of the protocol version
      */
      byte minor_version() const { return get_byte(1, m_version); }

      bool operator==(const Protocol_Version& other) const
         {
         return (m_version == other.m_version);
         }

      bool operator!=(const Protocol_Version& other) const
         {
         return (m_version != other.m_version);
         }

      bool operator>=(const Protocol_Version& other) const
         {
         return (m_version >= other.m_version);
         }

      bool operator>(const Protocol_Version& other) const
         {
         return (m_version > other.m_version);
         }

      bool operator<=(const Protocol_Version& other) const
         {
         return (m_version <= other.m_version);
         }

      bool operator<(const Protocol_Version& other) const
         {
         return (m_version < other.m_version);
         }

      std::string to_string() const;

   private:
      u16bit m_version;
   };

}

}

#endif

