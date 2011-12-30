/*
* TLS Extensions
* (C) 2011 Jack Lloyd
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
