/*
* X.509 Name Constraint
* (C) 2015 Kai Michaelis
*     2024,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/ber_dec.h>
#include <botan/uri.h>
#include <botan/x509cert.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/x509_utils.h>
#include <span>

namespace Botan {

class DER_Encoder;

namespace {

enum class RequireFQDN : bool { Yes = true, No = false };

/*
* Validate a host constraint - either a DNS name or a subtree of the
* form of "." followed by a DNS name. RFC 5280 4.2.1.10 defines this
* style for URI and email constraints. For DNS it is silent, but it
* seems in practice implementations accept subtrees for DNS
* constraints as well.
*/
std::optional<std::string> validate_subtree_constraint_host(std::string_view input, RequireFQDN require_fqdn) {
   if(input.empty()) {
      return std::nullopt;
   }
   const bool subtree = input.starts_with('.');
   const std::string_view body = subtree ? input.substr(1) : input;
   auto dns = DNSName::from_string(body);
   if(!dns.has_value()) {
      return std::nullopt;
   }
   if(require_fqdn == RequireFQDN::Yes && dns->to_string().find('.') == std::string::npos) {
      return std::nullopt;
   }

   if(subtree) {
      return std::string(".") + dns->to_string();
   } else {
      return dns->to_string();
   }
}

}  // namespace

std::optional<GeneralName::DNSConstraint> GeneralName::DNSConstraint::from_string(std::string_view input) {
   // TODO(C++23): validate_subtree_constraint_host(input, RequireFQDN::No)
   //                        .transform([](std::string s) { return DNSConstraint(std::move(s)); });
   if(auto canonical = validate_subtree_constraint_host(input, RequireFQDN::No)) {
      return DNSConstraint(std::move(*canonical));
   } else {
      return std::nullopt;
   }
}

std::optional<GeneralName::DNSConstraint> GeneralName::DNSConstraint::from_san_value(std::string_view input) {
   if(auto parsed = DNSName::from_san_string(input)) {
      return DNSConstraint(parsed->to_string());
   } else {
      return std::nullopt;
   }
}

std::optional<GeneralName::URIConstraint> GeneralName::URIConstraint::from_string(std::string_view input) {
   /*
   RFC 5280 4.2.1.10:
      The constraint MUST be specified as a fully qualified domain
      name and MAY specify a host or a domain.  Examples would be
      "host.example.com" and ".example.com".
   */
   if(auto canonical = validate_subtree_constraint_host(input, RequireFQDN::Yes)) {
      return URIConstraint(std::move(*canonical));
   } else {
      return std::nullopt;
   }
}

std::optional<GeneralName::URIConstraint> GeneralName::URIConstraint::from_san_value(std::string_view full_uri) {
   if(URI::parse(full_uri).has_value()) {
      return URIConstraint(std::string(full_uri));
   } else {
      return std::nullopt;
   }
}

std::optional<GeneralName::EmailConstraint> GeneralName::EmailConstraint::from_string(std::string_view input) {
   if(input.empty()) {
      return std::nullopt;
   }
   if(input.find('@') != std::string_view::npos) {
      // Mailbox form:
      auto email = EmailAddress::from_string(input);
      if(!email.has_value()) {
         return std::nullopt;
      }
      return EmailConstraint(email->to_string());
   }
   if(auto canonical = validate_subtree_constraint_host(input, RequireFQDN::No)) {
      // Host form
      return EmailConstraint(std::move(*canonical));
   }
   return std::nullopt;
}

namespace {

/*
* Match a single DNS label against an RFC 6125 6.4.3 wildcard pattern
* label (containing exactly one '*'). The candidate must have no dots
* (it is a single label).
*/
bool wildcard_label_matches(std::string_view pattern_label, std::string_view candidate) {
   if(candidate.find('.') != std::string_view::npos) {
      return false;
   }
   const auto star = pattern_label.find('*');
   if(star == std::string_view::npos) {
      return pattern_label == candidate;
   }
   const auto prefix = pattern_label.substr(0, star);
   const auto suffix = pattern_label.substr(star + 1);
   if(candidate.size() < prefix.size() + suffix.size()) {
      return false;
   }
   return candidate.starts_with(prefix) && candidate.ends_with(suffix);
}

}  // namespace

/*
* Does the wildcard SAN @p pattern have some expansion that falls inside the
* excluded DNS subtree @p constraint?
*
* This function is similar to but subtly different from host_wildcard_match,
* which is trying to answer a different question, namely "is `host` a name that
* a client should trust this wildcard cert for", including various checks such
* as the maximum length of labels. In contrast here we want to check for any
* possible overlap - could this wildcard expand to any name inside the excluded
* subtree.
*/
bool wildcard_intersects_excluded_dns_subtree(std::string_view pattern, std::string_view constraint) {
   if(pattern.empty() || constraint.empty()) {
      return false;
   }
   const bool subtree_form = (constraint.front() == '.');
   const std::string_view c_base = subtree_form ? constraint.substr(1) : constraint;
   if(c_base.empty()) {
      return false;
   }

   const auto first_dot = pattern.find('.');
   const std::string_view p_left = (first_dot == std::string_view::npos) ? pattern : pattern.substr(0, first_dot);
   const std::string_view p_tail =
      (first_dot == std::string_view::npos) ? std::string_view{} : pattern.substr(first_dot);

   if(p_tail.empty()) {
      // Single-label wildcard. Matches single-label names only, so it
      // can only land inside a bare-host subtree whose base is also a
      // single label.
      if(subtree_form || c_base.find('.') != std::string_view::npos) {
         return false;
      }
      return wildcard_label_matches(p_left, c_base);
   }

   // p_tail starts with ".". If it ends (label-aligned) with "." + c_base,
   // then every wildcard expansion produces a name ending with that
   // suffix, which is inside c_base's subtree (both bare-host and
   // leading-dot forms accept proper-subdomain entries).
   if(auto suffix_len = checked_add(c_base.size(), size_t{1})) {
      if(p_tail.size() >= *suffix_len) {
         const auto tail_suffix = p_tail.substr(p_tail.size() - *suffix_len);
         if(tail_suffix.front() == '.' && tail_suffix.substr(1) == c_base) {
            return true;
         }
      }
   }

   // Bare-host subtrees also contain c_base itself. The wildcard can
   // produce c_base directly iff c_base = (single label) + p_tail and
   // the prefix label fits p_left.
   if(!subtree_form && c_base.size() > p_tail.size() && c_base.substr(c_base.size() - p_tail.size()) == p_tail) {
      const auto x_view = c_base.substr(0, c_base.size() - p_tail.size());
      return wildcard_label_matches(p_left, x_view);
   }

   return false;
}

namespace {

/*
* RFC 5280 subtree matching for DNS-form names: a bare-host constraint
* matches the host itself or any name with extra leading labels (so
* "host.example.com" matches "host.example.com" and "www.host.example.com"
* but not "host1.example.com"). A constraint with a leading dot matches
* proper subdomains only.
*
* Used as-is for DNS name constraints. URI / RFC822 host-form constraints
* differ from this -- they're exact-match only on the bare-host form, and
* only the leading-dot ".host" form here is shared with them. Callers
* dispatch the leading-dot case to this helper.
*
* Both inputs are assumed to already be lowercased.
*/
bool dns_subtree_match(std::string_view name, std::string_view constraint) {
   // Embedded nulls should have been rejected during decoding before this point
   BOTAN_ASSERT_NOMSG(name.find('\0') == std::string_view::npos);

   if(name.size() == constraint.size()) {
      return name == constraint;
   } else if(constraint.size() > name.size()) {
      // The constraint is longer than the issued name: not possibly a match
      return false;
   }

   if(constraint.empty()) {
      return true;
   }

   BOTAN_ASSERT_NOMSG(name.size() > constraint.size());

   const std::string_view substr = name.substr(name.size() - constraint.size());

   if(constraint.front() == '.') {
      return substr == constraint;
   } else {
      return substr == constraint && name[name.size() - constraint.size() - 1] == '.';
   }
}

/*
* RFC 5280 4.2.1.10 RFC822 name constraint matching.
*
* The constraint @p c is one of:
*   - "local@host"    - matches exactly one mailbox (case-insensitive)
*   - "host"          - matches addresses whose domain is exactly host
*   - ".host"         - matches addresses in any subdomain of host
*                       (but NOT the base host itself)
*
* @p c is assumed to be already lowercased and validated at decode time.
*/
bool email_subtree_match(const EmailAddress& candidate, std::string_view c) {
   /*
   RFC 5280 7.5:
      Two email addresses are considered to match if:
         1)  the local-part of each name is an exact match, AND
         2)  the host-part of each name matches using a case-insensitive
             ASCII comparison.

   The candidate's domain comes through DNSName as canonical-lowercase, and the
   constraint string was lowercased only on its host portion at decode, so a
   plain string compare on each side produces the correct result.
   */
   const std::string& candidate_domain = candidate.domain().to_string();
   const auto at = c.find('@');
   if(at != std::string_view::npos) {
      // Mailbox form: exact-match against candidate
      return (candidate.local_part() == c.substr(0, at)) && (candidate_domain == c.substr(at + 1));
   }
   if(!c.empty() && c.front() == '.') {
      // Subtree form: any subdomain, but not the base host.
      return dns_subtree_match(candidate_domain, c);
   }
   /*
   RFC 5280 4.2.1.10:
      To indicate all Internet mail addresses on a particular host, the
      constraint is specified as the host name.  For example, the
      constraint "example.com" is satisfied by any mail address at the
      host "example.com".
   */
   return candidate_domain == c;
}

}  // namespace

std::string GeneralName::type() const {
   switch(m_type) {
      case NameType::Unknown:
         throw Encoding_Error("Could not convert unknown NameType to string");
      case NameType::RFC822:
         return "RFC822";
      case NameType::DNS:
         return "DNS";
      case NameType::URI:
         return "URI";
      case NameType::DN:
         return "DN";
      case NameType::IPv4:
         return "IP";
      case NameType::IPv6:
         return "IPv6";
      case NameType::Other:
         return "Other";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

GeneralName GeneralName::email(std::string_view email) {
   if(auto constraint = EmailConstraint::from_string(email)) {
      return {NameType::RFC822, std::move(*constraint)};
   } else {
      throw Invalid_Argument(fmt("Invalid RFC822 name constraint '{}'", email));
   }
}

GeneralName GeneralName::dns(std::string_view dns) {
   if(auto constraint = DNSConstraint::from_string(dns)) {
      return {NameType::DNS, std::move(*constraint)};
   } else {
      throw Invalid_Argument(fmt("Invalid DNS name constraint '{}'", dns));
   }
}

GeneralName GeneralName::uri(std::string_view uri) {
   if(auto constraint = URIConstraint::from_string(uri)) {
      return {NameType::URI, std::move(*constraint)};
   } else {
      throw Invalid_Argument(fmt("Invalid URI name constraint '{}'", uri));
   }
}

GeneralName GeneralName::_uri_san_value(std::string_view full_uri) {
   if(auto uri = URIConstraint::from_san_value(full_uri)) {
      return {NameType::URI, std::move(*uri)};
   } else {
      throw Invalid_Argument(fmt("Invalid URI SAN value '{}'", full_uri));
   }
}

GeneralName GeneralName::_dns_san_value(std::string_view dns_name) {
   if(auto dns = DNSConstraint::from_san_value(dns_name)) {
      return {NameType::DNS, std::move(*dns)};
   } else {
      throw Invalid_Argument(fmt("Invalid DNS SAN value '{}'", dns_name));
   }
}

GeneralName GeneralName::directory_name(Botan::X509_DN dn) {
   return {NameType::DN, std::move(dn)};
}

GeneralName GeneralName::ipv4_address(uint32_t ipv4) {
   return GeneralName::ipv4_address(IPv4Address(ipv4));
}

GeneralName GeneralName::ipv4_address(uint32_t ipv4, uint32_t mask) {
   if(auto subnet = IPv4Subnet::from_address_and_mask(ipv4, mask)) {
      return {NameType::IPv4, *subnet};
   } else {
      throw Invalid_Argument("IPv4 subnet mask is not a contiguous CIDR prefix");
   }
}

GeneralName GeneralName::ipv4_address(IPv4Address ipv4) {
   return {NameType::IPv4, IPv4Subnet::host(ipv4)};
}

GeneralName GeneralName::ipv4_address(const IPv4Subnet& subnet) {
   return {NameType::IPv4, subnet};
}

GeneralName GeneralName::ipv6_address(const IPv6Address& ipv6) {
   return {NameType::IPv6, IPv6Subnet::host(ipv6)};
}

GeneralName GeneralName::ipv6_address(const IPv6Subnet& subnet) {
   return {NameType::IPv6, subnet};
}

std::string GeneralName::name() const {
   return std::visit(
      Botan::overloaded{
         [](const EmailConstraint& c) -> std::string { return c.value(); },
         [](const DNSConstraint& c) -> std::string { return c.value(); },
         [](const URIConstraint& c) -> std::string { return c.value(); },
         [](const X509_DN& dn) -> std::string { return dn.to_string(); },
         [](const IPv4Subnet& s) -> std::string { return s.is_host() ? s.address().to_string() : s.to_string(); },
         [](const IPv6Subnet& s) -> std::string { return s.is_host() ? s.address().to_string() : s.to_string(); },
      },
      m_name);
}

std::vector<uint8_t> GeneralName::binary_name() const {
   return std::visit(Botan::overloaded{
                        [](const Botan::X509_DN& dn) { return Botan::ASN1::put_in_sequence(dn.get_bits()); },
                        [](const IPv4Subnet& subnet) { return subnet.serialize(); },
                        [](const IPv6Subnet& subnet) { return subnet.serialize(); },
                        [](const auto&) -> std::vector<uint8_t> {
                           throw Invalid_State("Cannot convert GeneralName to binary string");
                        },
                     },
                     m_name);
}

void GeneralName::encode_into(DER_Encoder& /*to*/) const {
   throw Not_Implemented("GeneralName encoding");
}

void GeneralName::decode_from(BER_Decoder& ber) {
   const BER_Object obj = ber.get_next_object();

   if(obj.is_a(0, ASN1_Class::ExplicitContextSpecific)) {
      m_type = NameType::Other;
   } else if(obj.is_a(1, ASN1_Class::ContextSpecific)) {
      /*
      RFC 5280 4.2.1.10:
         A name constraint for Internet mail addresses MAY specify a
         particular mailbox, all addresses at a particular host, or all
         mailboxes in a domain.
      EmailConstraint::from_string validates and canonicalizes per the
      Section 7.5 matching rules.
      */
      auto constraint = EmailConstraint::from_string(ASN1::to_string(obj));
      if(!constraint.has_value()) {
         throw Decoding_Error("Malformed RFC822 name in GeneralName");
      }
      m_type = NameType::RFC822;
      m_name = std::move(*constraint);
   } else if(obj.is_a(2, ASN1_Class::ContextSpecific)) {
      auto constraint = DNSConstraint::from_string(ASN1::to_string(obj));
      if(!constraint.has_value()) {
         throw Decoding_Error("Malformed DNS name in GeneralName");
      }
      m_type = NameType::DNS;
      m_name = std::move(*constraint);
   } else if(obj.is_a(6, ASN1_Class::ContextSpecific)) {
      /*
      RFC 5280 4.2.1.10:
         For URIs, the constraint applies to the host part of the name.
         The constraint MUST be specified as a fully qualified domain
         name and MAY specify a host or a domain.  Examples would be
         "host.example.com" and ".example.com".
      */
      auto constraint = URIConstraint::from_string(ASN1::to_string(obj));
      if(!constraint.has_value()) {
         throw Decoding_Error("Malformed URI name in GeneralName");
      }
      m_type = NameType::URI;
      m_name = std::move(*constraint);
   } else if(obj.is_a(4, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      X509_DN dn;
      BER_Decoder dec(obj, ber.limits());
      dn.decode_from(dec);
      dec.verify_end();
      m_type = NameType::DN;
      m_name.emplace<X509_DN>(dn);
   } else if(obj.is_a(7, ASN1_Class::ContextSpecific)) {
      if(obj.length() == 8) {
         const auto addr_and_mask = std::span<const uint8_t, 8>{obj.bits(), 8};
         auto subnet = IPv4Subnet::from_address_and_mask(addr_and_mask);
         if(!subnet.has_value()) {
            throw Decoding_Error("IPv4 name constraint mask is not a contiguous CIDR prefix");
         }

         m_type = NameType::IPv4;
         m_name.emplace<IPv4Subnet>(*subnet);
      } else if(obj.length() == 32) {
         const auto addr_and_mask = std::span<const uint8_t, 32>{obj.bits(), 32};
         auto subnet = IPv6Subnet::from_address_and_mask(addr_and_mask);
         if(!subnet.has_value()) {
            throw Decoding_Error("IPv6 name constraint mask is not a contiguous CIDR prefix");
         }

         m_type = NameType::IPv6;
         m_name.emplace<IPv6Subnet>(*subnet);
      } else {
         throw Decoding_Error("Invalid IP name constraint size " + std::to_string(obj.length()));
      }
   } else {
      m_type = NameType::Unknown;
   }
}

bool GeneralName::matches_dns(const std::string& dns_name) const {
   if(m_type == NameType::DNS) {
      return dns_subtree_match(dns_name, std::get<DNSConstraint>(m_name).value());
   }
   return false;
}

bool GeneralName::matches_dns(const DNSName& dns_name) const {
   if(m_type == NameType::DNS) {
      return dns_subtree_match(dns_name.to_string(), std::get<DNSConstraint>(m_name).value());
   }
   return false;
}

bool GeneralName::matches_ipv4(uint32_t ip) const {
   if(m_type == NameType::IPv4) {
      return std::get<IPv4Subnet>(m_name).contains(IPv4Address(ip));
   }
   return false;
}

bool GeneralName::matches_ipv6(const IPv6Address& ip) const {
   if(m_type == NameType::IPv6) {
      return std::get<IPv6Subnet>(m_name).contains(ip);
   }
   return false;
}

bool GeneralName::matches_dn(const X509_DN& dn) const {
   if(m_type == NameType::DN) {
      return matches_dn(dn, std::get<X509_DN>(m_name));
   }
   return false;
}

bool GeneralName::matches_uri(const URI& uri) const {
   if(m_type != NameType::URI) {
      return false;
   }
   // RFC 5280 4.2.1.10 does not provide for applying a DNS-form URI
   // constraint to an IP-literal host.
   if(uri.host_kind() != URI::HostKind::DNS) {
      return false;
   }
   const std::string& host = std::get<DNSName>(uri.host()).to_string();
   const std::string& constraint = std::get<URIConstraint>(m_name).value();
   /*
   RFC 5280 4.2.1.10:
      When the constraint begins with a period, it MAY be expanded with
      one or more labels.  That is, the constraint ".example.com" is
      satisfied by both host.example.com and my.host.example.com.
      However, the constraint ".example.com" is not satisfied by
      "example.com".  When the constraint does not begin with a period,
      it specifies a host.

   So a bare-host URI constraint is exact-match only; subdomains don't
   satisfy it. dns_subtree_match handles the leading-dot form correctly.
   */
   if(!constraint.empty() && constraint.front() == '.') {
      return dns_subtree_match(host, constraint);
   }
   return host == constraint;
}

bool GeneralName::matches_email(const EmailAddress& addr) const {
   if(m_type != NameType::RFC822) {
      return false;
   }
   return email_subtree_match(addr, std::get<EmailConstraint>(m_name).value());
}

bool GeneralName::matches_email(const SmtpUtf8Mailbox& mailbox) const {
   if(m_type != NameType::RFC822) {
      return false;
   }
   /*
   RFC 9598 Section 6:
      Setup converts the inputs of the comparison ... to constraint
      comparison form.  For both the name constraint and the subject,
      this will convert all A-labels and NR-LDH labels to lowercase.
      Strip the Local-part and "@" separator from each rfc822Name and
      SmtpUTF8Mailbox, which leaves just the domain part.  After setup,
      follow the comparison steps defined in Section 4.2.1.10 of
      [RFC5280] as follows.  If the resulting name constraint domain
      starts with a "." character, then for the name constraint to
      match, a suffix of the resulting subject alternative name domain
      MUST match the name constraint (including the leading ".") octet
      for octet.  If the resulting name constraint domain does not
      start with a "." character, then for the name constraint to
      match, the entire resulting subject alternative name domain MUST
      match the name constraint octet for octet.

   Per RFC 9598 Section 3 the SmtpUTF8Mailbox domain is already A-label /
   NR-LDH and lowercase by construction (DNSName::from_string enforces
   LDH + lowercase). The rfc822Name constraint flows through the same
   DNSName validation. So octet-for-octet comparison is the correct
   algorithm with no IDNA conversion required.
   */
   const std::string& candidate_domain = mailbox.domain().to_string();
   const std::string& constraint = std::get<EmailConstraint>(m_name).value();
   if(constraint.find('@') != std::string::npos) {
      /*
      * The situation with SmtpUTF8Mailbox mailbox constraints (with '@') is a bit confused.
      *
      * RFC 9549 updates RFC 5280 to completely drop support for mailbox constraints.
      * Then RFC 9598 Section 6 (relevant section quoted above) defines a mechanism to
      * apply rfc822 mailbox name constraints to SmtpUTF8Mailbox, but it does so in a
      * completely insecure way, namely by stripping off the local-part and comparing just
      * the domains. Under these rules, if an intermediate certificate had a permittedSubtrees
      * containing alice@example.com then a leaf certificate could have a SmtpUTF8Mailbox
      * containing bob@example.com, and per RFC 9598 that's fine because we are supposed
      * to just check the domains.
      *
      * This is obviously nonsense. Here we return false, which ensures that
      * is_permitted_smtp_utf8 never accepts on a mailbox constraint. In is_excluded_smtp_utf8
      * we first call matches_email then additionally (for mailbox constraints) reject any
      * matching domain using the additional check in mailbox_form_constraint_covers_domain.
      */
      return false;
   }
   if(!constraint.empty() && constraint.front() == '.') {
      // Leading-dot subtree form: suffix match including the dot.
      return candidate_domain.ends_with(constraint);
   }
   // Host form: exact match on the domain.
   return candidate_domain == constraint;
}

GeneralName::MatchResult GeneralName::matches(const X509_Certificate& cert) const {
   class MatchScore final {
      public:
         MatchScore() : m_any(false), m_some(false), m_all(true) {}

         void add(bool m) {
            m_any = true;
            m_some |= m;
            m_all &= m;
         }

         MatchResult result() const {
            if(!m_any) {
               return MatchResult::NotFound;
            } else if(m_all) {
               return MatchResult::All;
            } else if(m_some) {
               return MatchResult::Some;
            } else {
               return MatchResult::None;
            }
         }

      private:
         bool m_any;
         bool m_some;
         bool m_all;
   };

   const X509_DN& dn = cert.subject_dn();
   const AlternativeName& alt_name = cert.subject_alt_name();

   MatchScore score;

   if(m_type == NameType::DNS) {
      const auto& constraint = std::get<DNSConstraint>(m_name).value();

      for(const auto& dns : alt_name.dns_names()) {
         score.add(dns_subtree_match(dns.to_string(), constraint));
      }

      if(alt_name.is_empty()) {
         // TODO(Botan4): CN fallback is deprecated for removal in Botan4.
         // Check CN instead...
         for(const std::string& cn : dn.get_attribute("CN")) {
            if(cn.find('.') == std::string::npos) {
               continue;
            }
            if(IPv4Address::from_string(cn).has_value()) {
               continue;
            }
            if(auto dns_form = DNSName::from_san_string(cn)) {
               score.add(dns_subtree_match(dns_form->to_string(), constraint));
            }
         }
      }
   } else if(m_type == NameType::DN) {
      const X509_DN& constraint = std::get<X509_DN>(m_name);
      score.add(matches_dn(dn, constraint));

      for(const auto& alt_dn : alt_name.directory_names()) {
         score.add(matches_dn(alt_dn, constraint));
      }
   } else if(m_type == NameType::IPv4) {
      const auto& subnet = std::get<IPv4Subnet>(m_name);

      if(alt_name.is_empty()) {
         // TODO(Botan4): CN fallback is deprecated for removal in Botan4.
         // Check CN instead...
         for(const std::string& cn : dn.get_attribute("CN")) {
            if(auto ipv4 = IPv4Address::from_string(cn)) {
               score.add(subnet.contains(*ipv4));
            }
         }
      } else {
         for(const auto& ipv4 : alt_name.ipv4_addresses()) {
            score.add(subnet.contains(ipv4));
         }
      }
   } else if(m_type == NameType::IPv6) {
      for(const auto& ipv6 : alt_name.ipv6_addresses()) {
         score.add(matches_ipv6(ipv6));
      }
   } else if(m_type == NameType::URI) {
      for(const auto& uri : alt_name.uri_names()) {
         score.add(matches_uri(uri));
      }
   } else if(m_type == NameType::RFC822) {
      for(const auto& addr : alt_name.email_addresses()) {
         score.add(matches_email(addr));
      }
   } else {
      // Only NameType::Other (and the sentinel Unknown) remain; those
      // cannot be matched without per-OID semantics.
      return MatchResult::UnknownType;
   }

   return score.result();
}

//static
bool GeneralName::matches_dn(const X509_DN& name, const X509_DN& constraint) {
   /*
   RFC 5280 7.1:
     Two RelativeDistinguishedNames RDN1 and RDN2 match if they have
     the same number of naming attributes and for each naming attribute
     in RDN1 there is a matching naming attribute in RDN2.

   This is implementing directoryName subtree match, so the constraint's RDN
   sequence must be a prefix of the name's RDN sequence.
   */
   const auto& name_rdns = name.rdns();
   const auto& constraint_rdns = constraint.rdns();

   if(constraint_rdns.size() > name_rdns.size()) {
      return false;
   }

   for(size_t i = 0; i != constraint_rdns.size(); ++i) {
      if(!rdn_equality(constraint_rdns[i], name_rdns[i])) {
         return false;
      }
   }

   return true;
}

std::ostream& operator<<(std::ostream& os, const GeneralName& gn) {
   os << gn.type() << ":" << gn.name();
   return os;
}

GeneralSubtree::GeneralSubtree() = default;

void GeneralSubtree::encode_into(DER_Encoder& /*to*/) const {
   throw Not_Implemented("GeneralSubtree encoding");
}

void GeneralSubtree::decode_from(BER_Decoder& ber) {
   /*
   * RFC 5280 Section 4.2.1.10:
   *    Within this profile, the minimum and maximum fields are not used with any
   *    name forms, thus, the minimum MUST be zero, and maximum MUST be absent.
   */
   size_t minimum = 0;
   std::optional<size_t> maximum;

   ber.start_sequence()
      .decode(m_base)
      .decode_optional(minimum, ASN1_Type(0), ASN1_Class::ContextSpecific, size_t(0))
      .decode_optional(maximum, ASN1_Type(1), ASN1_Class::ContextSpecific)
      .end_cons();

   if(minimum != 0) {
      throw Decoding_Error("GeneralSubtree minimum must be 0");
   }
   if(maximum.has_value()) {
      throw Decoding_Error("GeneralSubtree maximum must be absent");
   }
}

std::ostream& operator<<(std::ostream& os, const GeneralSubtree& gs) {
   os << gs.base();
   return os;
}

NameConstraints::NameConstraints(std::vector<GeneralSubtree>&& permitted_subtrees,
                                 std::vector<GeneralSubtree>&& excluded_subtrees) :
      m_permitted_subtrees(std::move(permitted_subtrees)), m_excluded_subtrees(std::move(excluded_subtrees)) {
   for(const auto& c : m_permitted_subtrees) {
      m_permitted_name_types.insert(c.base().type_code());
   }
   for(const auto& c : m_excluded_subtrees) {
      m_excluded_name_types.insert(c.base().type_code());
   }
}

namespace {

bool exceeds_limit(size_t dn_count, size_t alt_count, size_t constraint_count) {
   /**
   * OpenSSL uses a similar limit, but applies it to the total number of
   * constraints, while we apply it to permitted and excluded independently.
   */
   constexpr size_t MAX_NC_CHECKS = (1 << 16);

   if(auto names = checked_add(dn_count, alt_count)) {
      if(auto product = checked_mul(*names, constraint_count)) {
         if(*product < MAX_NC_CHECKS) {
            return false;
         }
      }
   }
   return true;
}

}  // namespace

bool NameConstraints::is_permitted(const X509_Certificate& cert, bool reject_unknown) const {
   if(permitted().empty()) {
      return true;
   }

   const auto& alt_name = cert.subject_alt_name();

   if(exceeds_limit(cert.subject_dn().count(), alt_name.count(), permitted().size())) {
      return false;
   }

   if(reject_unknown) {
      /* A critical NC restricting an unrecognized GeneralName form (e.g. x400Address)
      * causes immediate rejection.
      *
      * RFC 5280 4.2.1.10 leaves this both unspecified
      *   The syntax and semantics for name constraints for otherName, ediPartyName, and
      *   registeredID are not defined by this specification
      * and discouraged
      *    Conforming CAs [...] SHOULD NOT impose name constraints on the x400Address,
      *    ediPartyName, or registeredID name forms.
      *
      * In principle we should only reject when the constrained form appears in the
      * certificate. But this situation in general seems to be a minefield, with no help
      * from specs, test suites, etc. Lacking any obvious use case, just fail closed.
      *
      * If you happen to hit this with a real chain, open an issue.
      */
      if(m_permitted_name_types.contains(GeneralName::NameType::Unknown)) {
         return false;
      }
      if(m_permitted_name_types.contains(GeneralName::NameType::Other) && !alt_name.other_name_values().empty()) {
         return false;
      }
   }

   auto is_permitted_dn = [&](const X509_DN& dn) {
      // If no restrictions, then immediate accept
      if(!m_permitted_name_types.contains(GeneralName::NameType::DN)) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_dn(dn)) {
            return true;
         }
      }

      // There is at least one permitted name and we didn't match
      return false;
   };

   auto is_permitted_dns_name = [&](const DNSName& name) {
      // If no restrictions, then immediate accept
      if(!m_permitted_name_types.contains(GeneralName::NameType::DNS)) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_dns(name)) {
            return true;
         }
      }

      // There is at least one permitted name and we didn't match
      return false;
   };

   /*
   RFC 5280 4.2.1.10: iPAddress is a single GeneralName element where
   IPv4 and IPv6 are distinguished only by the length.

   An iPAddress subtree of either version therefore restricts the iPAddress name
   form for both versions.
   */
   const bool ip_form_restricted = m_permitted_name_types.contains(GeneralName::NameType::IPv4) ||
                                   m_permitted_name_types.contains(GeneralName::NameType::IPv6);

   auto is_permitted_ipv4 = [&](const IPv4Address& ipv4) {
      if(!ip_form_restricted) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_ipv4(ipv4)) {
            return true;
         }
      }

      // We might here check if there are any IPv6 permitted names which are
      // mapped IPv4 addresses, and if so check if any of those apply. It's not
      // clear if this is desirable, and RFC 5280 is completely silent on the issue.

      // There is at least one permitted iPAddress name and we didn't match
      return false;
   };

   auto is_permitted_ipv6 = [&](const IPv6Address& ipv6) {
      if(!ip_form_restricted) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_ipv6(ipv6)) {
            return true;
         }
      }

      // There is at least one permitted iPAddress name and we didn't match
      return false;
   };

   auto is_permitted_uri = [&](const URI& uri) {
      // If no URI restrictions, accept.
      if(!m_permitted_name_types.contains(GeneralName::NameType::URI)) {
         return true;
      }
      /*
      RFC 5280 4.2.1.10:
         If a constraint is applied to the uniformResourceIdentifier
         name form and a subsequent certificate includes a
         subjectAltName extension with a uniformResourceIdentifier that
         does not include an authority component with a host name
         specified as a fully qualified domain name (e.g., if the URI
         either does not include an authority component or includes an
         authority component in which the host name is specified as an
         IP address), then the application MUST reject the certificate.
      */
      if(uri.host_kind() != URI::HostKind::DNS) {
         return false;
      }
      if(std::get<DNSName>(uri.host()).to_string().find('.') == std::string::npos) {
         return false;
      }
      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_uri(uri)) {
            return true;
         }
      }
      return false;
   };

   auto is_permitted_email = [&](const EmailAddress& addr) {
      // If no email restrictions, accept.
      if(!m_permitted_name_types.contains(GeneralName::NameType::RFC822)) {
         return true;
      }
      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_email(addr)) {
            return true;
         }
      }
      return false;
   };

   // RFC 9598 Section 6 extends rfc822Name name constraints to SmtpUTF8Mailbox
   // SAN entries (id-on-SmtpUTF8Mailbox otherNames). When rfc822Name
   // constraints are in effect, every SmtpUTF8Mailbox SAN must match
   // at least one permitted entry.
   auto is_permitted_smtp_utf8 = [&](const SmtpUtf8Mailbox& mailbox) {
      if(!m_permitted_name_types.contains(GeneralName::NameType::RFC822)) {
         return true;
      }
      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_email(mailbox)) {
            return true;
         }
      }
      return false;
   };

   /*
   RFC 5280 4.1.2.6:
      If subject naming information is present only in the
      subjectAltName extension (e.g., a key bound only to an email
      address or URI), then the subject name MUST be an empty
      sequence and the subjectAltName extension MUST be critical.

   RFC 5280 4.2.1.10:
      Restrictions of the form directoryName MUST be applied to the subject
      field in the certificate (when the certificate includes a non-empty
      subject field) and to any names of type directoryName in the
      subjectAltName extension.
   */
   if(!cert.subject_dn().empty() && !is_permitted_dn(cert.subject_dn())) {
      return false;
   }

   for(const auto& alt_dn : alt_name.directory_names()) {
      if(!is_permitted_dn(alt_dn)) {
         return false;
      }
   }

   for(const auto& alt_dns : alt_name.dns_names()) {
      if(!is_permitted_dns_name(alt_dns)) {
         return false;
      }
   }

   for(const auto& alt_ipv4 : alt_name.ipv4_addresses()) {
      if(!is_permitted_ipv4(alt_ipv4)) {
         return false;
      }
   }

   for(const auto& alt_ipv6 : alt_name.ipv6_addresses()) {
      if(!is_permitted_ipv6(alt_ipv6)) {
         return false;
      }
   }

   for(const auto& uri : alt_name.uri_names()) {
      if(!is_permitted_uri(uri)) {
         return false;
      }
   }

   for(const auto& addr : alt_name.email_addresses()) {
      if(!is_permitted_email(addr)) {
         return false;
      }
   }

   for(const auto& mailbox : alt_name.smtp_utf8_mailboxes()) {
      if(!is_permitted_smtp_utf8(mailbox)) {
         return false;
      }
   }

   // TODO(Botan4): CN fallback is deprecated for removal in Botan4.
   if(alt_name.is_empty()) {
      for(const auto& cn : cert.subject_info("CN")) {
         if(auto ipv4 = IPv4Address::from_string(cn)) {
            if(!is_permitted_ipv4(*ipv4)) {
               return false;
            }
         } else if(cn.find('.') != std::string::npos) {
            if(auto dns_form = DNSName::from_san_string(cn)) {
               if(!is_permitted_dns_name(*dns_form)) {
                  return false;
               }
            }
         }
      }

      /*
      RFC 5280 4.2.1.10:
         When constraints are imposed on the rfc822Name name form, but the
         certificate does not include a subject alternative name, the
         rfc822Name constraint MUST be applied to the attribute of type
         emailAddress in the subject distinguished name.
      */
      for(const auto& email_str : cert.subject_dn().get_attribute("PKCS9.EmailAddress")) {
         if(auto addr = EmailAddress::from_string(email_str)) {
            if(!is_permitted_email(*addr)) {
               return false;
            }
         } else if(m_permitted_name_types.contains(GeneralName::NameType::RFC822)) {
            // emailAddress is present but unparsable and an rfc822Name
            // constraint is in effect; treat as not permitted.
            return false;
         }
      }
   }

   // We didn't encounter a name that doesn't have a matching constraint
   return true;
}

bool NameConstraints::is_excluded(const X509_Certificate& cert, bool reject_unknown) const {
   if(excluded().empty()) {
      return false;
   }

   const auto& alt_name = cert.subject_alt_name();

   if(exceeds_limit(cert.subject_dn().count(), alt_name.count(), excluded().size())) {
      return true;
   }

   if(reject_unknown) {
      // This is one is overly broad: we should just reject if there is a name constraint
      // with the same OID as one of the other names
      if(m_excluded_name_types.contains(GeneralName::NameType::Other) && !alt_name.other_name_values().empty()) {
         return true;
      }
      // As in is_permitted: a critical NC restricting an unrecognized
      // GeneralName form cannot be evaluated; reject conservatively.
      if(m_excluded_name_types.contains(GeneralName::NameType::Unknown)) {
         return true;
      }
   }

   auto is_excluded_dn = [&](const X509_DN& dn) {
      // If no restrictions, then immediate accept
      if(!m_excluded_name_types.contains(GeneralName::NameType::DN)) {
         return false;
      }

      for(const auto& c : m_excluded_subtrees) {
         if(c.base().matches_dn(dn)) {
            return true;
         }
      }

      // There is at least one excluded name and we didn't match
      return false;
   };

   auto is_excluded_dns_name = [&](const DNSName& name) {
      // If no restrictions, then immediate accept
      if(!m_excluded_name_types.contains(GeneralName::NameType::DNS)) {
         return false;
      }

      for(const auto& c : m_excluded_subtrees) {
         if(c.base().matches_dns(name)) {
            return true;
         }

         /*
         RFC 5280 4.2.1.10:
            Any name matching a restriction in the excludedSubtrees
            field is invalid regardless of information appearing in
            the permittedSubtrees.

         If the cert has a wildcard SAN (*.example.com), and that wildcard
         could be matched against an excluded name, it must be rejected.
         */
         if(c.base().m_type == GeneralName::NameType::DNS && name.is_wildcard()) {
            const auto& constraint = std::get<GeneralName::DNSConstraint>(c.base().m_name).value();
            if(wildcard_intersects_excluded_dns_subtree(name.to_string(), constraint)) {
               return true;
            }
         }
      }

      // There is at least one excluded name and we didn't match
      return false;
   };

   auto is_excluded_ipv4 = [&](const IPv4Address& ipv4) {
      if(m_excluded_name_types.contains(GeneralName::NameType::IPv4)) {
         for(const auto& c : m_excluded_subtrees) {
            if(c.base().matches_ipv4(ipv4)) {
               return true;
            }
         }
      }

      // This name did not match any of the excluded names
      return false;
   };

   auto is_excluded_ipv6 = [&](const IPv6Address& ipv6) {
      if(m_excluded_name_types.contains(GeneralName::NameType::IPv6)) {
         for(const auto& c : m_excluded_subtrees) {
            if(c.base().matches_ipv6(ipv6)) {
               return true;
            }
         }
      }

      // An IPv4-mapped IPv6 address names an IPv4 address so verify that
      // address is not restricted by an IPv4 excludes rule
      if(m_excluded_name_types.contains(GeneralName::NameType::IPv4)) {
         if(auto embedded_v4 = ipv6.as_ipv4()) {
            for(const auto& c : m_excluded_subtrees) {
               if(c.base().matches_ipv4(*embedded_v4)) {
                  return true;
               }
            }
         }
      }

      // This name did not match any of the excluded names
      return false;
   };

   auto is_excluded_uri = [&](const URI& uri) {
      if(!m_excluded_name_types.contains(GeneralName::NameType::URI)) {
         return false;
      }
      /*
      RFC 5280 4.2.1.10:
         If a constraint is applied to the uniformResourceIdentifier
         name form and a subsequent certificate includes a
         subjectAltName extension with a uniformResourceIdentifier that
         does not include an authority component with a host name
         specified as a fully qualified domain name (e.g., if the URI
         either does not include an authority component or includes an
         authority component in which the host name is specified as an
         IP address), then the application MUST reject the certificate.
      */
      if(uri.host_kind() != URI::HostKind::DNS) {
         return true;
      }
      if(std::get<DNSName>(uri.host()).to_string().find('.') == std::string::npos) {
         return true;
      }
      for(const auto& c : m_excluded_subtrees) {
         if(c.base().matches_uri(uri)) {
            return true;
         }
      }
      return false;
   };

   /*
   * The email matching logic on the exclude side is intentionally stricter
   * (more expansive) than the permit side logic.
   *
   * RFC 9549 updates RFC 5280 and among other things completely removes mailbox
   * form constraints (ones with a '@', rather than just a domain constraint)
   * claiming "This capability was not used".
   *
   * This prohibition is reiterated in RFC 9598 Section 6 with "rfc822Name
   * constraints with a Local-part SHOULD NOT be used."
   *
   * Here we lean very conservative in our interpretation: if there is a
   * mailbox-form exclude constraint, we reject any mailbox at that domain. That
   * is, if excludedSubtrees includes "user@example.com", we treat that
   * constraint identically to an exclusion of "example.com".
   *
   * This might be overly cautious, but generally a rejects-valid bug gets you a
   * prompt bug report with testcase, while an accepts-invalid eventually gets
   * you a surprise CVE.
   */
   auto mailbox_form_constraint_covers_domain = [](const GeneralName& gn, const DNSName& san_domain) {
      if(gn.type_code() != GeneralName::NameType::RFC822) {
         return false;
      }
      const auto& constraint = std::get<GeneralName::EmailConstraint>(gn.m_name).value();
      const auto at = constraint.find('@');
      return at != std::string::npos && san_domain.to_string() == constraint.substr(at + 1);
   };

   auto is_excluded_email = [&](const EmailAddress& addr) {
      if(m_excluded_name_types.contains(GeneralName::NameType::RFC822)) {
         for(const auto& c : m_excluded_subtrees) {
            if(c.base().matches_email(addr)) {
               return true;
            }
            /*
            If we were strictly following RFC 9549 we would here want to call
            mailbox_form_constraint_covers_domain, but this breaks chains which
            are in conformance to the specifications prior to 9549.
            */
         }
      }
      return false;
   };

   // RFC 9598 Section 6: rfc822Name name constraints also apply to
   // SmtpUTF8Mailbox SAN entries. See is_permitted_smtp_utf8.
   auto is_excluded_smtp_utf8 = [&](const SmtpUtf8Mailbox& mailbox) {
      if(m_excluded_name_types.contains(GeneralName::NameType::RFC822)) {
         for(const auto& c : m_excluded_subtrees) {
            if(c.base().matches_email(mailbox)) {
               return true;
            }
            if(mailbox_form_constraint_covers_domain(c.base(), mailbox.domain())) {
               return true;
            }
         }
      }
      return false;
   };

   if(is_excluded_dn(cert.subject_dn())) {
      return true;
   }

   for(const auto& alt_dn : alt_name.directory_names()) {
      if(is_excluded_dn(alt_dn)) {
         return true;
      }
   }

   for(const auto& alt_dns : alt_name.dns_names()) {
      if(is_excluded_dns_name(alt_dns)) {
         return true;
      }
   }

   for(const auto& alt_ipv4 : alt_name.ipv4_addresses()) {
      if(is_excluded_ipv4(alt_ipv4)) {
         return true;
      }
   }

   for(const auto& alt_ipv6 : alt_name.ipv6_addresses()) {
      if(is_excluded_ipv6(alt_ipv6)) {
         return true;
      }
   }

   for(const auto& uri : alt_name.uri_names()) {
      if(is_excluded_uri(uri)) {
         return true;
      }
   }

   for(const auto& addr : alt_name.email_addresses()) {
      if(is_excluded_email(addr)) {
         return true;
      }
   }

   for(const auto& mailbox : alt_name.smtp_utf8_mailboxes()) {
      if(is_excluded_smtp_utf8(mailbox)) {
         return true;
      }
   }

   // TODO(Botan4): CN fallback is deprecated for removal in Botan4.
   if(alt_name.is_empty()) {
      for(const auto& cn : cert.subject_info("Name")) {
         if(auto ipv4 = IPv4Address::from_string(cn)) {
            if(is_excluded_ipv4(*ipv4)) {
               return true;
            }
         } else if(cn.find('.') != std::string::npos) {
            if(auto dns_form = DNSName::from_san_string(cn)) {
               if(is_excluded_dns_name(*dns_form)) {
                  return true;
               }
            }
         }
      }

      // RFC 5280 4.2.1.10 fallback to subject DN emailAddress when the cert has no SAN
      for(const auto& email_str : cert.subject_dn().get_attribute("PKCS9.EmailAddress")) {
         if(auto addr = EmailAddress::from_string(email_str)) {
            if(is_excluded_email(*addr)) {
               return true;
            }
         } else if(m_excluded_name_types.contains(GeneralName::NameType::RFC822)) {
            return true;
         }
      }
   }

   // We didn't encounter a name that matched any prohibited name
   return false;
}

}  // namespace Botan
