/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/uri.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/charset.h>
#include <botan/internal/parsing.h>

namespace Botan {

namespace {

std::optional<uint16_t> parse_port(std::string_view s) {
   const auto digit_from_ascii = [](char c) -> std::optional<uint32_t> {
      if(c >= '0' && c <= '9') {
         return c - '0';
      } else {
         return {};
      }
   };

   if(s.empty() || s.size() > 5) {
      return {};
   }

   uint32_t port = 0;

   for(const char c : s) {
      if(auto digit = digit_from_ascii(c)) {
         // Integer overflow impossible here since we checked max length of s earlier
         port = port * 10 + *digit;
      } else {
         return {};
      }
   }

   if(port == 0 || port >= 65536) {
      return {};
   }

   return static_cast<uint16_t>(port);
}

bool is_valid_percent_escape(char c1, char c2) {
   auto is_hex_digit = [](char c) {
      return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
   };

   if(!is_hex_digit(c1) || !is_hex_digit(c2)) {
      return false;
   }

   // Proactively reject embedded null (%00)
   if(c1 == '0' && c2 == '0') {
      return false;
   }

   return true;
}

bool validate_path_query_fragment(std::string_view tail) {
   /*
   * RFC 3986 syntax for the path/query/fragment of a URI:
   *
   *   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
   *   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
   *   segment       = *pchar
   *   path-abempty  = *( "/" segment )
   *   query         = *( pchar / "/" / "?" )
   *   fragment     =  *( pchar / "/" / "?" )
   */

   constexpr auto is_pchar_or_slash = CharacterValidityTable::alpha_numeric_plus("-._~!$&'()*+,;=:@/");

   enum class State : uint8_t { Path, Query, Fragment };
   State state = State::Path;

   for(size_t i = 0; i < tail.size(); ++i) {
      const char c = tail[i];
      if(c == '%') {
         if(i + 2 >= tail.size() || !is_valid_percent_escape(tail[i + 1], tail[i + 2])) {
            return false;
         }
         i += 2;
         continue;
      }
      if(c == '?') {
         // First '?' transitions from path to query, any further '?' are literal
         if(state == State::Path) {
            state = State::Query;
         }
         continue;
      }
      if(c == '#') {
         // There is only one '#' fragment delimiter, second '#' is invalid
         if(state == State::Fragment) {
            return false;
         }
         state = State::Fragment;
         continue;
      }
      if(!is_pchar_or_slash(c)) {
         return false;
      }
   }
   return true;
}

bool validate_userinfo(std::string_view userinfo) {
   constexpr auto is_valid_userinfo_char = CharacterValidityTable::alpha_numeric_plus("-._~!$&'()*+,;=:");

   for(size_t i = 0; i < userinfo.size(); ++i) {
      const char c = userinfo[i];
      if(c == '%') {
         if(i + 2 >= userinfo.size() || !is_valid_percent_escape(userinfo[i + 1], userinfo[i + 2])) {
            return false;
         }
         i += 2;
         continue;
      }
      if(!is_valid_userinfo_char(c)) {
         return false;
      }
   }
   return true;
}

}  // namespace

std::strong_ordering URI::operator<=>(const URI& other) const {
   return std::tie(m_scheme, m_authority, m_path, m_query, m_fragment) <=>
          std::tie(other.m_scheme, other.m_authority, other.m_path, other.m_query, other.m_fragment);
}

bool URI::operator==(const URI& other) const {
   return m_scheme == other.m_scheme && m_authority == other.m_authority && m_path == other.m_path &&
          m_query == other.m_query && m_fragment == other.m_fragment;
}

std::strong_ordering URI::Authority::operator<=>(const URI::Authority& other) const {
   /*
   Userinfo is compared without normalization; RFC 3986 6.2.2.1:
      When a URI uses components of the generic syntax, the component
      syntax equivalence rules always apply; namely, that the scheme
      and host are case-insensitive and therefore should be normalized
      to lowercase. ... The other generic syntax components are assumed
      to be case-sensitive unless specifically defined otherwise by the
      scheme.
   */
   return std::tie(m_userinfo, m_host, m_port) <=> std::tie(other.m_userinfo, other.m_host, other.m_port);
}

bool URI::Authority::operator==(const URI::Authority& other) const {
   return m_userinfo == other.m_userinfo && m_host == other.m_host && m_port == other.m_port;
}

//static
std::optional<URI> URI::parse(std::string_view raw) {
   // Empty string is not a valid URI
   if(raw.empty()) {
      return {};
   }

   // RFC 3986:
   // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
   constexpr auto is_scheme_cont_char = CharacterValidityTable::alpha_numeric_plus("+-.");

   const auto is_ascii_alpha = [](char c) -> bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); };

   // Check the first scheme character
   if(!is_ascii_alpha(raw.front())) {
      return {};
   }

   // Scan the rest of the scheme
   size_t i = 1;
   while(i < raw.size() && is_scheme_cont_char(raw[i])) {
      ++i;
   }
   // Scheme wasn't followed by ':' -> invalid
   if(i >= raw.size() || raw[i] != ':') {
      return {};
   }

   // Canonicalize the scheme
   const std::string scheme = tolower_string(raw.substr(0, i));

   // The scheme must be followed by "//" introducing an authority. RFC 5280
   // does allow including URIs without an authority ("urn:of:cat:ashes",
   // "mailto:root@attacker.com") but they seem like an potential footgun (for
   // example a rfc822 name constraint will not apply to a mailto: URL) and
   // without any obvious justification to support here.

   auto rest = raw.substr(i + 1);
   if(rest.size() < 2 || rest[0] != '/' || rest[1] != '/') {
      return {};
   }
   rest.remove_prefix(2);  // Strip off the '//'

   // Authority runs to the first '/', '?' or '#'. The remaining is `path ? query # fragment`,
   // which is validated against the RFC 3986 character set.
   const auto end = rest.find_first_of("/?#");
   const auto authority = (end == std::string_view::npos) ? rest : rest.substr(0, end);
   const auto path_query_fragment = (end == std::string_view::npos) ? std::string_view{} : rest.substr(end);

   // Parse and validate the authority string (hostname, IPv4, or IPv6 address)
   auto parsed_authority = Authority::parse(authority);
   if(!parsed_authority.has_value()) {
      return {};
   }

   // Validate any `path ? query # fragment` portions of the URL
   if(!validate_path_query_fragment(path_query_fragment)) {
      return {};
   }

   // Split into path / query / fragment. Validation above guarantees at most
   // one '#', so the first '#' is the fragment delimiter, and within the
   // pre-fragment portion the first '?' (if any) is the query delimiter.
   const auto hash = path_query_fragment.find('#');
   const auto pre_fragment =
      (hash == std::string_view::npos) ? path_query_fragment : path_query_fragment.substr(0, hash);
   std::optional<std::string> fragment;
   if(hash != std::string_view::npos) {
      fragment = std::string(path_query_fragment.substr(hash + 1));
   }

   const auto qmark = pre_fragment.find('?');
   const auto path = (qmark == std::string_view::npos) ? pre_fragment : pre_fragment.substr(0, qmark);
   std::optional<std::string> query;
   if(qmark != std::string_view::npos) {
      query = std::string(pre_fragment.substr(qmark + 1));
   }

   // Accept
   return URI(
      std::string(raw), scheme, std::move(*parsed_authority), std::string(path), std::move(query), std::move(fragment));
}

//static
std::optional<URI::Authority> URI::Authority::parse(std::string_view raw) {
   if(raw.empty()) {
      return {};
   }

   /*
   RFC 3986
     userinfo = *( unreserved / pct-encoded / sub-delims / ":" )

   Thus a unencoded '@' is not allowed inside userinfo, and the single '@' splits the
   username from the authority. The @ being present at all is significant; an empty
   userinfo ("https://@example.com/") is distinct from no userinfo at all.
   */
   std::optional<std::string> userinfo;
   const auto first_at = raw.find('@');
   if(first_at != std::string_view::npos) {
      if(raw.find('@', first_at + 1) != std::string_view::npos) {
         return {};
      }
      const auto userinfo_view = raw.substr(0, first_at);
      if(!validate_userinfo(userinfo_view)) {
         return {};
      }
      userinfo = std::string(userinfo_view);
      raw.remove_prefix(first_at + 1);
   }

   std::string_view host_view;
   std::string_view port_str;
   std::optional<Host> host;

   if(!raw.empty() && raw.front() == '[') {
      // Bracketed IPv6 literal.
      const auto close = raw.find(']');
      if(close == std::string_view::npos) {
         return {};
      }
      host_view = raw.substr(1, close - 1);
      if(host_view.empty()) {
         return {};
      }
      const auto after = raw.substr(close + 1);
      if(!after.empty()) {
         if(after.front() != ':') {
            return {};
         }
         port_str = after.substr(1);
      }
      auto ipv6 = IPv6Address::from_string(host_view);
      if(!ipv6.has_value()) {
         return {};
      }
      host = *ipv6;
   } else {
      // host[:port] with no brackets. Only one ':' is allowed (port).
      const auto colon = raw.find(':');
      if(colon == std::string_view::npos) {
         host_view = raw;
      } else {
         host_view = raw.substr(0, colon);
         port_str = raw.substr(colon + 1);

         // Verify the `:` char is the only one that appears
         if(port_str.find(':') != std::string::npos) {
            return {};
         }
      }

      if(host_view.empty()) {
         return {};
      }

      // Technically valid per RFC 3986 but likely not something we want to support
      if(host_view.ends_with('.')) {
         return {};
      }

      if(auto ipv4 = IPv4Address::from_string(host_view)) {
         host = *ipv4;
      } else if(auto dns = DNSName::from_string(host_view)) {
         host = std::move(*dns);
      } else {
         return {};
      }
   }

   std::optional<uint16_t> port;

   if(!port_str.empty()) {
      port = parse_port(port_str);
      if(!port.has_value()) {
         return {};
      }
   }

   return Authority(std::string(raw), std::move(userinfo), std::move(*host), port);
}

std::string URI::Authority::host_to_string() const {
   return std::visit([](const auto& h) -> std::string { return h.to_string(); }, m_host);
}

URI::Authority::HostKind URI::Authority::host_kind() const {
   if(std::holds_alternative<DNSName>(m_host)) {
      return HostKind::DNS;
   } else if(std::holds_alternative<IPv4Address>(m_host)) {
      return HostKind::IPv4;
   } else if(std::holds_alternative<IPv6Address>(m_host)) {
      return HostKind::IPv6;
   } else {
      BOTAN_ASSERT_UNREACHABLE();
   }
}

//static
std::vector<URI> URI::filter_scheme(std::string_view scheme, std::span<const URI> uris) {
   std::vector<URI> results;

   const auto normalized_scheme = tolower_string(scheme);

   for(const auto& uri : uris) {
      if(uri.scheme() == normalized_scheme) {
         results.push_back(uri);
      }
   }

   return results;
}

}  // namespace Botan
