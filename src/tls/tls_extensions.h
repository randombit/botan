/*
* TLS Extensions
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_EXTENSIONS_H__
#define BOTAN_TLS_EXTENSIONS_H__

#include <botan/secmem.h>
#include <botan/tls_magic.h>
#include <vector>
#include <string>

namespace Botan {

class TLS_Session;
class TLS_Data_Reader;

/**
* Base class representing a TLS extension of some kind
*/
class TLS_Extension
   {
   public:
      virtual TLS_Handshake_Extension_Type type() const = 0;
      virtual MemoryVector<byte> serialize() const = 0;

      virtual bool empty() const = 0;

      virtual ~TLS_Extension() {}
   };

/**
* Server Name Indicator extension (RFC 3546)
*/
class Server_Name_Indicator : public TLS_Extension
   {
   public:
      TLS_Handshake_Extension_Type type() const
         { return TLSEXT_SERVER_NAME_INDICATION; }

      Server_Name_Indicator(const std::string& host_name) :
         sni_host_name(host_name) {}

      Server_Name_Indicator(TLS_Data_Reader& reader,
                            u16bit extension_size);

      std::string host_name() const { return sni_host_name; }

      MemoryVector<byte> serialize() const;

      bool empty() const { return sni_host_name == ""; }
   private:
      std::string sni_host_name;
   };

/**
* SRP identifier extension (RFC 5054)
*/
class SRP_Identifier : public TLS_Extension
   {
   public:
      TLS_Handshake_Extension_Type type() const
         { return TLSEXT_SRP_IDENTIFIER; }

      SRP_Identifier(const std::string& identifier) :
         srp_identifier(identifier) {}

      SRP_Identifier(TLS_Data_Reader& reader,
                     u16bit extension_size);

      std::string identifier() const { return srp_identifier; }

      MemoryVector<byte> serialize() const;

      bool empty() const { return srp_identifier == ""; }
   private:
      std::string srp_identifier;
   };

/**
* Renegotiation Indication Extension (RFC 5746)
*/
class Renegotation_Extension : public TLS_Extension
   {
   public:
      TLS_Handshake_Extension_Type type() const
         { return TLSEXT_SAFE_RENEGOTIATION; }

      Renegotation_Extension() {}

      Renegotation_Extension(const MemoryRegion<byte>& bits) :
         reneg_data(bits) {}

      Renegotation_Extension(TLS_Data_Reader& reader,
                             u16bit extension_size);

      const MemoryVector<byte>& renegotiation_info() const
         { return reneg_data; }

      MemoryVector<byte> serialize() const;

      bool empty() const { return false; } // always send this
   private:
      MemoryVector<byte> reneg_data;
   };

/**
* Maximum Fragment Length Negotiation Extension (RFC 4366 sec 3.2)
*/
class Maximum_Fragment_Length : public TLS_Extension
   {
   public:
      TLS_Handshake_Extension_Type type() const
         { return TLSEXT_MAX_FRAGMENT_LENGTH; }

      bool empty() const { return val != 0; }

      size_t fragment_size() const;

      MemoryVector<byte> serialize() const
         {
         return MemoryVector<byte>(&val, 1);
         }

      /**
      * @param max_fragment specifies what maximum fragment size to
      *        advertise. Currently must be one of 512, 1024, 2048, or
      *        4096.
      */
      Maximum_Fragment_Length(size_t max_fragment);

      Maximum_Fragment_Length(TLS_Data_Reader& reader,
                              u16bit extension_size);

   private:
      byte val;
   };

/**
* Next Protocol Negotiation
* http://technotes.googlecode.com/git/nextprotoneg.html
*
* This implementation requires the semantics defined in the Google
* spec (implemented in Chromium); the internet draft leaves the format
* unspecified.
*/
class Next_Protocol_Notification : public TLS_Extension
   {
   public:
      TLS_Handshake_Extension_Type type() const
         { return TLSEXT_NEXT_PROTOCOL; }

      const std::vector<std::string>& protocols() const
         { return m_protocols; }

      /**
      * Empty extension, used by client
      */
      Next_Protocol_Notification() {}

      /**
      * List of protocols, used by server
      */
      Next_Protocol_Notification(const std::vector<std::string>& protocols) :
         m_protocols(protocols) {}

      Next_Protocol_Notification(TLS_Data_Reader& reader,
                                 u16bit extension_size);

      MemoryVector<byte> serialize() const;

      bool empty() const { return false; }
   private:
      std::vector<std::string> m_protocols;
   };

class Session_Ticket : public TLS_Extension
   {
   public:
      TLS_Handshake_Extension_Type type() const
         { return TLSEXT_SESSION_TICKET; }

      const MemoryVector<byte>& contents() const { return m_contents; }

      /**
      * Create empty extension, used by both client and server
      */
      Session_Ticket() {}

      /**
      * Extension with ticket, used by client
      */
      Session_Ticket(const MemoryRegion<byte>& session_ticket) :
         m_contents(session_ticket) {}

      /**
      * Deserialize a session ticket
      */
      Session_Ticket(const TLS_Data_Reader& reader, u16bit extension_size);

      MemoryVector<byte> serialize() const { return m_contents; }

      bool empty() const { return false; }
   private:
      MemoryVector<byte> m_contents;
   };

/**
* Represents a block of extensions in a hello message
*/
class TLS_Extensions
   {
   public:
      size_t count() const { return extensions.size(); }

      TLS_Extension* at(size_t idx) { return extensions.at(idx); }

      void push_back(TLS_Extension* extn)
         { extensions.push_back(extn); }

      MemoryVector<byte> serialize() const;

      TLS_Extensions() {}

      TLS_Extensions(TLS_Data_Reader& reader); // deserialize

      ~TLS_Extensions();
   private:
      TLS_Extensions(const TLS_Extensions&) {}
      TLS_Extensions& operator=(const TLS_Extensions&) { return (*this); }

      std::vector<TLS_Extension*> extensions;
   };

}

#endif
