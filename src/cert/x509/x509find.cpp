/*
* X.509 Certificate Store Searching
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509find.h>
#include <botan/charset.h>
#include <algorithm>

namespace Botan {

namespace X509_Store_Search {

namespace {

/*
* Compare based on case-insensive substrings
*/
bool substring_match(const std::string& searching_for,
                     const std::string& found)
   {
   if(std::search(found.begin(), found.end(), searching_for.begin(),
                  searching_for.end(), Charset::caseless_cmp) != found.end())
      return true;
   return false;
   }

/*
* Compare based on case-insensive match
*/
bool ignore_case(const std::string& searching_for, const std::string& found)
   {
   if(searching_for.size() != found.size())
      return false;

   return std::equal(found.begin(), found.end(),
                     searching_for.begin(), Charset::caseless_cmp);
   }

}

/*
* Search based on the contents of a DN entry
*/
std::function<bool (const X509_Certificate&)>
by_dn(const std::string& dn_entry,
      const std::string& to_find,
      DN_Search_Type method)
   {
   if(method == SUBSTRING_MATCHING)
      return by_dn(dn_entry, to_find, substring_match);
   else if(method == IGNORE_CASE)
      return by_dn(dn_entry, to_find, ignore_case);

   throw Invalid_Argument("Unknown method argument to by_dn");
   }

std::function<bool (const X509_Certificate&)>
by_dn(const std::string& dn_entry,
      const std::string& to_find,
      std::function<bool (std::string, std::string)> compare)
   {
   return [&](const X509_Certificate& cert)
      {
      std::vector<std::string> info = cert.subject_info(dn_entry);

      for(u32bit i = 0; i != info.size(); ++i)
         if(compare(info[i], to_find))
            return true;
      return false;
      };
   }

std::function<bool (const X509_Certificate&)>
by_issuer_and_serial(const X509_DN& issuer, const MemoryRegion<byte>& serial)
   {
   /* Serial number compare is much faster than X.509 DN, and unlikely
   to collide even across issuers, so do that first to fail fast
   */

   return [&](const X509_Certificate& cert)
      {
      if(cert.serial_number() != serial)
         return false;
      return (cert.issuer_dn() == issuer);
      };
   }

std::function<bool (const X509_Certificate&)>
by_issuer_and_serial(const X509_DN& issuer, const BigInt& serial)
   {
   return by_issuer_and_serial(issuer, BigInt::encode(serial));
   }

std::function<bool (const X509_Certificate&)>
by_skid(const MemoryRegion<byte>& subject_key_id)
   {
   return [&](const X509_Certificate& cert)
      {
      return (cert.subject_key_id() == subject_key_id);
      };
   }

}

}
