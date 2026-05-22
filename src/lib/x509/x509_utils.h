/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_UTILS_H_
#define BOTAN_X509_UTILS_H_

#include <botan/asn1_obj.h>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Botan {

inline std::optional<uint32_t> is_sub_element_of(const OID& oid, std::initializer_list<uint32_t> prefix) {
   const auto& c = oid.get_components();

   if(c.size() != prefix.size() + 1) {
      return {};
   }

   if(!std::equal(c.begin(), c.end() - 1, prefix.begin(), prefix.end())) {
      return {};
   }

   return c[c.size() - 1];
}

/*
* X.500 String Comparison
*/
bool x500_name_cmp(std::string_view name1, std::string_view name2);

/*
* X.500 string canonicalization: applies the same case-fold and whitespace
* normalization that x500_name_cmp performs internally, producing a string
* that can be used as a sort/hash key.
*/
std::string x500_canonicalize_value(std::string_view name);

/*
* Set-equality comparison of two RDNs (each a SET OF AttributeTypeAndValue).
* RFC 5280 7.1: two RDNs match if they have the same number of naming
* attributes and each attribute in one has a matching attribute in the other.
*/
bool rdn_equality(const std::vector<std::pair<OID, ASN1_String>>& a, const std::vector<std::pair<OID, ASN1_String>>& b);

/*
* Does the wildcard SAN @p pattern have some expansion that falls
* inside the excluded DNS subtree @p constraint? Used by
* NameConstraints to check whether a wildcard SAN could resolve to a
* name inside an excludedSubtrees entry, regardless of whether a TLS
* client would actually trust the wildcard for that name.
*
* @p pattern must contain a single '*' in the leftmost label
* (DNSName::from_san_string guarantees this for SAN values).
* @p constraint is the DNS name-constraint value (bare-host or
* leading-dot form). Both inputs assumed lowercased.
*/
BOTAN_TEST_API
bool wildcard_intersects_excluded_dns_subtree(std::string_view pattern, std::string_view constraint);

}  // namespace Botan

#endif
