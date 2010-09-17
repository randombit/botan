/*
* Certificate Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/certstor.h>

namespace Botan {

/*
* Search by name
*/
std::vector<X509_Certificate>
Certificate_Store::by_name(const std::string&) const
   {
   return std::vector<X509_Certificate>();
   }

/*
* Search by email
*/
std::vector<X509_Certificate>
Certificate_Store::by_email(const std::string&) const
   {
   return std::vector<X509_Certificate>();
   }

/*
* Search by X.500 distinguished name
*/
std::vector<X509_Certificate>
Certificate_Store::by_dn(const X509_DN&) const
   {
   return std::vector<X509_Certificate>();
   }

/*
* Find any CRLs that might be useful
*/
std::vector<X509_CRL>
Certificate_Store::get_crls_for(const X509_Certificate&) const
   {
   return std::vector<X509_CRL>();
   }

}
