/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_URI_H_
#define BOTAN_URI_H_

#include <botan/dns_name.h>
#include <botan/ipv4_address.h>
#include <botan/ipv6_address.h>
#include <botan/types.h>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace Botan {

/**
* URI (RFC 3986 subset)
*/
class BOTAN_PUBLIC_API(3, 13) URI final {
   public:
      /**
      * The authority component of a URI: a validated DNS name, IPv4 literal,
      * or IPv6 literal, with an optional port.
      */
      class BOTAN_PUBLIC_API(3, 13) Authority final {
         public:
            /**
            * A validated DNS name, or a literal IPv4 or IPv6 address.
            */
            using Host = std::variant<DNSName, IPv4Address, IPv6Address>;

            /*
            * Tag for the alternative held by `Host`.
            */
            enum class HostKind : uint8_t {
               DNS = 0,
               IPv4 = 1,
               IPv6 = 2,
            };

            /**
            * Parse a bare authority "host[:port]" or "[ipv6][:port]".
            * Returns nullopt for any parse failure.
            */
            static std::optional<Authority> parse(std::string_view raw);

            /**
            * Parsed host: a DNS name, an IPv4 literal, or an IPv6 literal.
            */
            const Host& host() const { return m_host; }

            /**
            * Which alternative of `host()` is held.
            */
            HostKind host_kind() const;

            /**
            * The host as a string: DNS names and dotted-IPv4 literals are
            * returned verbatim; IPv6 literals are returned without surrounding
            * brackets. Lowercased for DNS / IPv4; the IPv6 form is whatever
            * `IPv6Address::to_string` produces.
            */
            std::string host_to_string() const;

            /**
            * Port if present; nullopt otherwise.
            */
            std::optional<uint16_t> port() const { return m_port; }

            /**
            * The original input that was parsed
            */
            const std::string& original_input() const { return m_raw; }

            /**
            * The userinfo component, preserved verbatim (no case normalization
            * or pct-decoding) and compared verbatim for identity. nullopt if no
            * "@" was present; present-but-empty (e.g. "https://@example.com/")
            * is distinguished from absent.
            */
            const std::optional<std::string>& userinfo() const { return m_userinfo; }

            std::strong_ordering operator<=>(const Authority& other) const;

            bool operator==(const Authority& other) const;

         private:
            Authority(std::string raw, std::optional<std::string> userinfo, Host host, std::optional<uint16_t> port) :
                  m_raw(std::move(raw)), m_userinfo(std::move(userinfo)), m_host(std::move(host)), m_port(port) {}

            std::string m_raw;
            std::optional<std::string> m_userinfo;
            Host m_host;
            std::optional<uint16_t> m_port;
      };

      using Host = Authority::Host;
      using HostKind = Authority::HostKind;

      /**
      * Parse a URI, return nullopt on failure
      */
      static std::optional<URI> parse(std::string_view raw);

      /**
      * Return the scheme, lowercase normalized
      */
      const std::string& scheme() const { return m_scheme; }

      /**
      * Return the parsed URI authority.
      */
      const Authority& authority() const { return m_authority; }

      /**
      * Return the parsed host; a DNS name, an IPv4 literal, or an IPv6 literal.
      */
      const Host& host() const { return m_authority.host(); }

      /**
      * Which alternative of `host()` is held.
      */
      HostKind host_kind() const { return m_authority.host_kind(); }

      /**
      * Return the host as a string.
      */
      std::string host_to_string() const { return m_authority.host_to_string(); }

      /**
      * Return the port if present; nullopt otherwise.
      */
      std::optional<uint16_t> port() const { return m_authority.port(); }

      /**
      * The path component, preserved verbatim. Begins with "/" when present;
      * empty if the parsed URI had no path (e.g. "http://example.com" or
      * "http://example.com?q").
      */
      const std::string& path() const { return m_path; }

      /**
      * The query component, without the leading "?". Nullopt if no "?" was
      * present; present-but-empty distinguishes "http://h/p?" from
      * "http://h/p".
      */
      const std::optional<std::string>& query() const { return m_query; }

      /**
      * The fragment component, without the leading "#". Nullopt if no "#"
      * was present; present-but-empty distinguishes "http://h/p#" from
      * "http://h/p".
      */
      const std::optional<std::string>& fragment() const { return m_fragment; }

      /**
      * The original input that was parsed.
      */
      const std::string& original_input() const { return m_raw; }

      std::strong_ordering operator<=>(const URI& other) const;

      bool operator==(const URI& other) const;

      /**
      * Return a list of URIs (possibly empty) which match the specified scheme
      */
      static std::vector<URI> filter_scheme(std::string_view scheme, std::span<const URI> uris);

   private:
      URI(std::string raw,
          std::string scheme,
          Authority authority,
          std::string path,
          std::optional<std::string> query,
          std::optional<std::string> fragment) :
            m_raw(std::move(raw)),
            m_scheme(std::move(scheme)),
            m_authority(std::move(authority)),
            m_path(std::move(path)),
            m_query(std::move(query)),
            m_fragment(std::move(fragment)) {}

      std::string m_raw;
      std::string m_scheme;
      Authority m_authority;
      std::string m_path;
      std::optional<std::string> m_query;
      std::optional<std::string> m_fragment;
};

}  // namespace Botan

#endif
