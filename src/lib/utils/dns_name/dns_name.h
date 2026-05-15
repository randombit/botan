/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DNS_NAME_H_
#define BOTAN_DNS_NAME_H_

#include <botan/types.h>
#include <optional>
#include <string>
#include <string_view>

namespace Botan {

/**
* A DNS name (host name or wildcard pattern) in canonical form.
*
* Construction validates that the input conforms to the Preferred Name
* Syntax (RFC 1035 / RFC 1123 LDH labels, length limits, no leading or
* trailing dot). The stored form is lowercased ASCII.
*/
class BOTAN_PUBLIC_API(3, 13) DNSName final {
   public:
      /**
      * Parse and canonicalize a literal hostname. Returns nullopt if the
      * input is not a valid DNS name per RFC 1035 / 1123, or if it
      * contains a "*" label (use `from_san_string` for that).
      */
      static std::optional<DNSName> from_string(std::string_view name);

      /**
      * Like `from_string`, but additionally accepts the RFC 6125 6.4.3
      * wildcard form: a single "*" anywhere within the leftmost label
      * of an otherwise-valid DNS name (e.g. "*.example.com",
      * "foo*.example.com", bare "*"). Shapes that could never produce
      * a match - multiple "*" ("*.*.example.com") or "*" outside the
      * leftmost label ("foo.*.example.com") - are rejected. Intended
      * for parsing X.509 SAN dnsName entries.
      */
      static std::optional<DNSName> from_san_string(std::string_view name);

      const std::string& to_string() const { return m_name; }

      const std::string& name() const { return m_name; }

      /**
      * True if this name is a wildcard pattern: a single "*" somewhere
      * in the leftmost label, per RFC 6125 6.4.3 (which permits
      * in-label partial wildcards like "foo*.example.com" as well as
      * the complete-leftmost-label "*.example.com" form). Shapes
      * outside this form - multiple "*" or "*" not in the leftmost
      * label - are rejected at construction by `from_san_string`, so
      * any stored "*" is already in the leftmost label.
      */
      bool is_wildcard() const { return m_name.find('*') != std::string::npos; }

      /**
      * Test whether this name matches a wildcard pattern (e.g. "*.example.com").
      * The wildcard label must be the leftmost label. Comparison is
      * case-insensitive.
      */
      bool matches_wildcard(std::string_view wildcard) const;

      auto operator<=>(const DNSName&) const = default;
      bool operator==(const DNSName&) const = default;

      /**
      * Test if the issued name (which might be a wildcard pattern) can match the host,
      * which should be a complete and valid DNS name.
      *
      * Returns false if either the pattern or the host seem invalid
      */
      static bool host_wildcard_match(std::string_view issued, std::string_view host);

   private:
      explicit DNSName(std::string canonical) : m_name(std::move(canonical)) {}

      std::string m_name;
};

}  // namespace Botan

#endif
