/*
* Certificate Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CERT_STORE_H__
#define BOTAN_CERT_STORE_H__

#include <botan/x509cert.h>
#include <botan/x509_crl.h>

namespace Botan {

/*
* Certificate Store Interface
*/
class BOTAN_DLL Certificate_Store
   {
   public:
      virtual std::vector<X509_Certificate>
         by_SKID(const MemoryRegion<byte>&) const = 0;

      virtual std::vector<X509_Certificate> by_name(const std::string&) const;
      virtual std::vector<X509_Certificate> by_email(const std::string&) const;
      virtual std::vector<X509_Certificate> by_dn(const X509_DN&) const;

      virtual std::vector<X509_CRL>
         get_crls_for(const X509_Certificate&) const;

      virtual Certificate_Store* clone() const = 0;

      virtual ~Certificate_Store() {}
   };

}

#endif
