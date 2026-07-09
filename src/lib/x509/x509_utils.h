/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_UTILS_H_
#define BOTAN_X509_UTILS_H_

#include <botan/asn1_obj.h>
#include <algorithm>
#include <initializer_list>
#include <optional>
#include <string_view>

namespace Botan {

class X509_CRL;
class X509_Certificate;
class X509_DN;

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
* DirectoryName subtree match according to RFC 5280 7.1. The constraint's
* RDN sequence must be a prefix of the candidate name's RDN sequence.
*/
bool x509_dn_subtree_match(const X509_DN& name, const X509_DN& constraint);

/*
* Combined result of the two has_matching_distribution_point* questions:
*   - `any`: at least one DP (explicit or implicit) name-matches per
*     RFC 5280 6.3.3 (b)(1) and (b)(2)(i).
*   - `any_with_absent_reasons`: also true if a matching DP omits the reasons
*     field (or the match is via the implicit DP, which has no reasons by
*     construction).
* Sharing a single DP-loop pass between the two predicates keeps their
* matching rules in sync and avoids re-walking the cert's CDP.
*/
struct DistributionPointMatch {
      bool any;
      bool any_with_absent_reasons;
};

DistributionPointMatch distribution_point_match(const X509_CRL& crl, const X509_Certificate& cert);

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
