/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/email.h>

#include <botan/internal/charset.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

std::optional<std::pair<std::string, DNSName>> parse_email_address(std::string_view addr) {
   /*
   * RFC 5322 atext: ALPHA / DIGIT plus "!#$%&'*+-/=?^_`{|}~" (plus ".")
   *
   * Anything outside this set in the local part requires quoting,
   * which we deliberately don't accept.
   */
   constexpr auto is_atext_or_dot = CharacterValidityTable::alpha_numeric_plus(".!#$%&'*+-/=?^_`{|}~");

   if(addr.empty() || !is_valid_utf8(addr)) {
      return {};
   }

   const auto at = addr.find('@');

   // Must be one (and only one) @ sign
   if(at == std::string_view::npos || addr.find('@', at + 1) != std::string_view::npos) {
      return {};
   }

   // Split at the @ sign and verify both halves are non-empty
   const std::string_view local = addr.substr(0, at);
   const std::string_view domain = addr.substr(at + 1);

   if(local.empty() || domain.empty()) {
      return {};
   }

   // RFC 3696 section 3:
   //
   //  period (".") may also appear [in an email address local-part],
   //  but may not be used to start or end the local part, nor may two
   //  or more consecutive periods appear.

   // TODO(C++23): use std::string::contains
   if(local.starts_with('.') || local.ends_with('.') || local.find("..") != std::string_view::npos) {
      return {};
   }

   // RFC 5322 dot-atom. This intentionally omits support for quoting
   for(const char c : local) {
      // Here we accept high bit for UTF-8 for SmtpUtf8Mailbox
      if(!is_atext_or_dot(c) && static_cast<uint8_t>(c) < 0x80) {
         return {};
      }
   }

   auto parsed_domain = DNSName::from_string(domain);
   if(!parsed_domain.has_value()) {
      return {};
   }

   return std::make_pair(std::string(local), parsed_domain.value());
}

}  // namespace

std::string EmailAddress::to_string() const {
   return fmt("{}@{}", m_local_part, m_domain.to_string());
}

//static
std::optional<EmailAddress> EmailAddress::from_string(std::string_view addr) {
   auto parsed = parse_email_address(addr);

   if(parsed) {
      // Verify the local-part is all ASCII
      for(const char c : parsed->first) {
         if(static_cast<uint8_t>(c) >= 0x80) {
            return {};
         }
      }
      return EmailAddress(std::move(parsed->first), std::move(parsed->second));
   } else {
      return {};
   }
}

std::string SmtpUtf8Mailbox::to_string() const {
   return fmt("{}@{}", m_local_part, m_domain.to_string());
}

//static
std::optional<SmtpUtf8Mailbox> SmtpUtf8Mailbox::from_string(std::string_view addr) {
   auto parsed = parse_email_address(addr);

   if(parsed) {
      /*
      * RFC 9598 Section 3
      *   SmtpUTF8Mailbox subjectAltName MUST NOT be used unless the Local-part
      *   of the email address contains non-ASCII characters.  When the Local-
      *   part is ASCII, rfc822Name subjectAltName MUST be used instead of
      *   SmtpUTF8Mailbox.
      *
      * We do not currently enforce this on the decoding side.
      */
      return SmtpUtf8Mailbox(std::move(parsed->first), std::move(parsed->second));
   }

   return {};
}

}  // namespace Botan
