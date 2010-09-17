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
bool DN_Check::match(const X509_Certificate& cert) const
   {
   std::vector<std::string> info = cert.subject_info(dn_entry);

   for(u32bit j = 0; j != info.size(); ++j)
      if(compare(info[j], looking_for))
         return true;
   return false;
   }

/*
* DN_Check Constructor
*/
DN_Check::DN_Check(const std::string& dn_entry, const std::string& looking_for,
                   compare_fn func)
   {
   this->dn_entry = dn_entry;
   this->looking_for = looking_for;
   compare = func;
   }

/*
* DN_Check Constructor
*/
DN_Check::DN_Check(const std::string& dn_entry, const std::string& looking_for,
                   Search_Type method)
   {
   this->dn_entry = dn_entry;
   this->looking_for = looking_for;

   if(method == SUBSTRING_MATCHING)
      compare = &substring_match;
   else if(method == IGNORE_CASE)
      compare = &ignore_case;
   else
      throw Invalid_Argument("Unknown method argument to DN_Check()");
   }

/*
* Match by issuer and serial number
*/
bool IandS_Match::match(const X509_Certificate& cert) const
   {
   if(cert.serial_number() != serial)
      return false;
   return (cert.issuer_dn() == issuer);
   }

/*
* IandS_Match Constructor
*/
IandS_Match::IandS_Match(const X509_DN& issuer,
                         const MemoryRegion<byte>& serial)
   {
   this->issuer = issuer;
   this->serial = serial;
   }

/*
* Match by subject key identifier
*/
bool SKID_Match::match(const X509_Certificate& cert) const
   {
   return (cert.subject_key_id() == skid);
   }

}
