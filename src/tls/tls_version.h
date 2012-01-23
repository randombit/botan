/*
* TLS Protocol Version Management
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_PROTOCOL_VERSION_H__
#define BOTAN_TLS_PROTOCOL_VERSION_H__

#include <botan/get_byte.h>
#include <botan/parsing.h>

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

      Protocol_Version() : m_major(0), m_minor(0) {}

      Protocol_Version(Version_Code named_version) :
         m_major(get_byte<u16bit>(0, named_version)),
         m_minor(get_byte<u16bit>(1, named_version)) {}

      Protocol_Version(byte major, byte minor) : m_major(major), m_minor(minor) {}

      /**
      * Get the major version of the protocol version
      */
      byte major_version() const { return m_major; }

      /**
      * Get the minor version of the protocol version
      */
      byte minor_version() const { return m_minor; }

      bool operator==(const Protocol_Version& other) const
         {
         return (cmp(other) == 0);
         }

      bool operator!=(const Protocol_Version& other) const
         {
         return (cmp(other) != 0);
         }

      bool operator>=(const Protocol_Version& other) const
         {
         return (cmp(other) >= 0);
         }

      bool operator>(const Protocol_Version& other) const
         {
         return (cmp(other) > 0);
         }

      bool operator<=(const Protocol_Version& other) const
         {
         return (cmp(other) <= 0);
         }

      bool operator<(const Protocol_Version& other) const
         {
         return (cmp(other) < 0);
         }

      std::string to_string() const;

   private:
      s32bit cmp(const Protocol_Version& other) const
         {
         if(major_version() < other.major_version())
            return -1;
         if(major_version() > other.major_version())
            return 1;
         if(minor_version() < other.minor_version())
            return -1;
         if(minor_version() > other.minor_version())
            return 1;
         return 0;
         }

      byte m_major, m_minor;
   };

}

}

#endif

