/*
* X.509 Certificate Store Searching
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_CERT_STORE_SEARCH_H__
#define BOTAN_X509_CERT_STORE_SEARCH_H__

#include <botan/x509stor.h>
#include <botan/bigint.h>

namespace Botan {

namespace X509_Store_Search {

/*
* Search based on the contents of a DN entry
*/
enum DN_Search_Type { SUBSTRING_MATCHING, IGNORE_CASE };

std::function<bool (const X509_Certificate&)>
by_dn(const std::string& dn_entry,
          const std::string& to_find,
          DN_Search_Type method);

std::function<bool (const X509_Certificate&)>
by_dn(const std::string& dn_entry,
          const std::string& to_find,
          std::function<bool (std::string, std::string)> method);

/**
* Search for certs by issuer + serial number
*/
std::function<bool (const X509_Certificate&)>
by_issuer_and_serial(const X509_DN& issuer, const MemoryRegion<byte>& serial);

std::function<bool (const X509_Certificate&)>
by_issuer_and_serial(const X509_DN& issuer, const BigInt& serial);

/**
* Search for certs by subject key identifier
*/
std::function<bool (const X509_Certificate&)>
by_skid(const MemoryRegion<byte>& subject_key_id);

}

}

#endif
