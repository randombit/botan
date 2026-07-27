/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EMAIL_ADDRESS_H_
#define BOTAN_EMAIL_ADDRESS_H_

#include <botan/dns_name.h>
#include <botan/types.h>
#include <optional>
#include <string>
#include <string_view>

namespace Botan {

/**
* A parsed email address in mailbox form: "local-part@domain".
*
* This is specifically modeling RFC 5280's rfc822Name GeneralName type.
* In this type, the local-part of the email address must be an ASCII subset.
*
* This type and SmtpUTF8Mailbox are very similar in that both express mailbox
* names. However they are modeled as distinct and unrelated types, as certain
* name constraint processing rules are applied differently to the two name
* forms, so it is important that they not be confusable. In addition, by a
* strict reading of the RFCs, the names expressed by EmailAddress and by
* SmtpUTF8Mailbox are completely disjoint; EmailAddress as encoded can only
* express ASCII local-part names, and SmtpUTF8Mailbox is RFC MUST required to be
* used only for names with a non-ASCII local-part.
*/
class BOTAN_PUBLIC_API(3, 13) EmailAddress final {
   public:
      /**
      * Parse an rfc822Name mailbox
      * @param addr the address to parse
      * @return the parsed address, or nullopt if addr is not a valid rfc822Name
      */
      static std::optional<EmailAddress> from_string(std::string_view addr);

      /// The local-part, ASCII only
      const std::string& local_part() const { return m_local_part; }

      /// The domain part of the address
      /// @return the domain of the address
      const DNSName& domain() const { return m_domain; }

      /**
      * Format the address as "local-part@domain"
      * @return the text form of the address
      */
      std::string to_string() const;

      /**
      * Order two addresses
      * @return the ordering of this address relative to the other
      */
      auto operator<=>(const EmailAddress&) const = default;

      /**
      * Compare two addresses
      * @return true if the two addresses are equal
      */
      bool operator==(const EmailAddress&) const = default;

   private:
      EmailAddress(std::string local_part, DNSName domain) :
            m_local_part(std::move(local_part)), m_domain(std::move(domain)) {}

      std::string m_local_part;
      DNSName m_domain;
};

/**
* A parsed internationalized mailbox (`SmtpUTF8Mailbox`) as defined by RFC 9598.
*
* The mailbox is `local-part "@" domain`, where local-part is a UTF-8 string.
* The RFC specifically requires that this name only be used when the local-part
* of the name is not representable in ASCII.
*
* Prior specifications of this name (RFC 8398) allowed for any internationalized
* domains be stored as U-label names. However RFC 9598 changes this so that only
* A-label names are allowed. This restriction is enforced by this type.
*/
class BOTAN_PUBLIC_API(3, 13) SmtpUtf8Mailbox final {
   public:
      /**
      * Parse an SmtpUTF8Mailbox
      * @param addr the address to parse
      * @return the parsed address, or nullopt if addr is not a valid SmtpUTF8Mailbox
      */
      static std::optional<SmtpUtf8Mailbox> from_string(std::string_view addr);

      /// The local-part, UTF-8 encoded, should contain non-ASCII
      const std::string& local_part() const { return m_local_part; }

      /// The domain, as an LDH host name in A-label form (RFC 9598 Section 3)
      const DNSName& domain() const { return m_domain; }

      /**
      * Format the mailbox as "local-part@domain"
      * @return the text form of the mailbox
      */
      std::string to_string() const;

      /**
      * Order two mailboxes
      * @return the ordering of this mailbox relative to the other
      */
      auto operator<=>(const SmtpUtf8Mailbox&) const = default;

      /**
      * Compare two mailboxes
      * @return true if the two mailboxes are equal
      */
      bool operator==(const SmtpUtf8Mailbox&) const = default;

   private:
      SmtpUtf8Mailbox(std::string local_part, DNSName domain) :
            m_local_part(std::move(local_part)), m_domain(std::move(domain)) {}

      std::string m_local_part;
      DNSName m_domain;
};

}  // namespace Botan

#endif
