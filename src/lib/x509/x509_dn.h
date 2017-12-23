/*
* X.509 Distinguished Name
* (C) 1999-2010 Jack Lloyd
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_DN_H_
#define BOTAN_X509_DN_H_

#include <botan/asn1_obj.h>
#include <botan/asn1_oid.h>
#include <botan/asn1_str.h>
#include <map>
#include <iosfwd>

namespace Botan {

/**
* Distinguished Name
*/
class BOTAN_PUBLIC_API(2,0) X509_DN final : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const override;
      void decode_from(class BER_Decoder&) override;

      bool has_field(const std::string& attr) const;
      std::vector<std::string> get_attribute(const std::string& attr) const;

      std::string get_first_attribute(const std::string& attr) const;

      std::multimap<OID, std::string> get_attributes() const;
      std::multimap<std::string, std::string> contents() const;

      void add_attribute(const std::string& key, const std::string& val);
      void add_attribute(const OID& oid, const std::string& val);

      static std::string deref_info_field(const std::string& key);

      /**
      * Lookup upper bounds in characters for the length of distinguished name fields
      * as given in RFC 5280, Appendix A.
      *
      * @param oid the oid of the DN to lookup
      * @return the upper bound, or zero if no ub is known to Botan
      */
      static size_t lookup_ub(const OID& oid);

      /*
      * Return the BER encoded data, if any
      */
      const std::vector<uint8_t>& get_bits() const;

      bool empty() const { return m_dn_info.empty(); }

      X509_DN() = default;
      explicit X509_DN(const std::multimap<OID, std::string>& vals);
      explicit X509_DN(const std::multimap<std::string, std::string>& vals);
   private:
      std::multimap<OID, ASN1_String> m_dn_info;
      std::vector<uint8_t> m_dn_bits;
   };

bool BOTAN_PUBLIC_API(2,0) operator==(const X509_DN&, const X509_DN&);
bool BOTAN_PUBLIC_API(2,0) operator!=(const X509_DN&, const X509_DN&);
bool BOTAN_PUBLIC_API(2,0) operator<(const X509_DN&, const X509_DN&);

BOTAN_PUBLIC_API(2,0) std::ostream& operator<<(std::ostream& out, const X509_DN& dn);
BOTAN_PUBLIC_API(2,0) std::istream& operator>>(std::istream& in, X509_DN& dn);

}

#endif
