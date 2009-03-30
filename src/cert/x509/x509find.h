/*
* X.509 Certificate Store Searching
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_CERT_STORE_SEARCH_H__
#define BOTAN_X509_CERT_STORE_SEARCH_H__

#include <botan/x509stor.h>

namespace Botan {

/*
* Search based on the contents of a DN entry
*/
class BOTAN_DLL DN_Check : public X509_Store::Search_Func
   {
   public:
      typedef bool (*compare_fn)(const std::string&, const std::string&);
      enum Search_Type { SUBSTRING_MATCHING, IGNORE_CASE };

      bool match(const X509_Certificate& cert) const;

      DN_Check(const std::string&, const std::string&, compare_fn);
      DN_Check(const std::string&, const std::string&, Search_Type);
   private:
      std::string dn_entry, looking_for;
      compare_fn compare;
   };

/*
* Search for a certificate by issuer/serial
*/
class BOTAN_DLL IandS_Match : public X509_Store::Search_Func
   {
   public:
      bool match(const X509_Certificate& cert) const;
      IandS_Match(const X509_DN&, const MemoryRegion<byte>&);
   private:
      X509_DN issuer;
      MemoryVector<byte> serial;
   };

/*
* Search for a certificate by subject keyid
*/
class BOTAN_DLL SKID_Match : public X509_Store::Search_Func
   {
   public:
      bool match(const X509_Certificate& cert) const;
      SKID_Match(const MemoryRegion<byte>& s) : skid(s) {}
   private:
      MemoryVector<byte> skid;
   };

}

#endif
