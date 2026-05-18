/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>

namespace Botan {

void AlternativeName::add_uri(std::string_view uri) {
   if(uri.empty()) {
      return;
   }
   if(auto parsed = URI::parse(uri)) {
      m_uri.insert(std::move(*parsed));
   } else {
      throw Decoding_Error("Invalid URI in SubjectAlternativeName");
   }
}

std::set<std::string> AlternativeName::uris() const {
   std::set<std::string> out;
   for(const auto& uri : m_uri) {
      out.insert(uri.original_input());
   }
   return out;
}

void AlternativeName::add_email(std::string_view addr) {
   if(addr.empty()) {
      return;
   }
   if(auto parsed = EmailAddress::from_string(addr)) {
      m_email.insert(std::move(*parsed));
   } else {
      throw Decoding_Error("Invalid email address in SubjectAlternativeName");
   }
}

std::set<std::string> AlternativeName::email() const {
   std::set<std::string> out;
   for(const auto& addr : m_email) {
      out.insert(addr.to_string());
   }
   return out;
}

void AlternativeName::add_dns(std::string_view dns) {
   if(dns.empty()) {
      return;
   }
   if(auto parsed = DNSName::from_san_string(dns)) {
      m_dns.insert(std::move(*parsed));
   } else {
      throw Decoding_Error("Invalid DNS name in SubjectAlternativeName");
   }
}

std::set<std::string> AlternativeName::dns() const {
   std::set<std::string> out;
   for(const auto& name : m_dns) {
      out.insert(name.to_string());
   }
   return out;
}

void AlternativeName::add_other_name(const OID& oid, const ASN1_String& value) {
   m_othernames.insert(std::make_pair(oid, value));
   std::vector<uint8_t> raw;
   DER_Encoder(raw).encode(value);
   m_other_name_values.insert(OtherNameValue(oid, std::move(raw)));
}

void AlternativeName::add_other_name_value(const OID& oid, std::span<const uint8_t> value) {
   m_other_name_values.insert(OtherNameValue(oid, value));
}

void AlternativeName::add_registered_id(const OID& oid) {
   m_registered_ids.insert(oid);
}

void AlternativeName::add_dn(const X509_DN& dn) {
   m_dn_names.insert(dn);
}

void AlternativeName::add_ipv4_address(uint32_t ip) {
   m_ipv4_addr.insert(ip);
}

void AlternativeName::add_ipv6_address(const IPv6Address& ip) {
   m_ipv6_addr.insert(ip);
}

size_t AlternativeName::count() const {
   const auto sum = checked_add(m_dns.size(),
                                m_uri.size(),
                                m_email.size(),
                                m_ipv4_addr.size(),
                                m_ipv6_addr.size(),
                                m_dn_names.size(),
                                m_other_name_values.size(),
                                m_registered_ids.size());

   BOTAN_ASSERT_NOMSG(sum.has_value());
   return sum.value();
}

bool AlternativeName::has_items() const {
   return this->count() > 0;
}

void AlternativeName::encode_into(DER_Encoder& der) const {
   der.start_sequence();

   /*
   GeneralName ::= CHOICE {
        otherName                       [0]     OtherName,
        rfc822Name                      [1]     IA5String,
        dNSName                         [2]     IA5String,
        x400Address                     [3]     ORAddress,
        directoryName                   [4]     Name,
        ediPartyName                    [5]     EDIPartyName,
        uniformResourceIdentifier       [6]     IA5String,
        iPAddress                       [7]     OCTET STRING,
        registeredID                    [8]     OBJECT IDENTIFIER }
   */

   for(const auto& othername : m_other_name_values) {
      der.start_explicit(0)
         .encode(othername.oid())
         .start_explicit(0)
         .raw_bytes(othername.value())
         .end_explicit()
         .end_explicit();
   }

   for(const auto& addr : m_email) {
      const ASN1_String str(addr.to_string(), ASN1_Type::Ia5String);
      der.add_object(ASN1_Type(1), ASN1_Class::ContextSpecific, str.value());
   }

   for(const auto& name : m_dns) {
      const ASN1_String str(name.to_string(), ASN1_Type::Ia5String);
      der.add_object(ASN1_Type(2), ASN1_Class::ContextSpecific, str.value());
   }

   for(const auto& name : m_dn_names) {
      der.add_object(ASN1_Type(4), ASN1_Class::ExplicitContextSpecific, name.DER_encode());
   }

   for(const auto& name : m_uri) {
      const ASN1_String str(name.original_input(), ASN1_Type::Ia5String);
      der.add_object(ASN1_Type(6), ASN1_Class::ContextSpecific, str.value());
   }

   for(const uint32_t ip : m_ipv4_addr) {
      auto ip_buf = store_be(ip);
      // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
      der.add_object(ASN1_Type(7), ASN1_Class::ContextSpecific, ip_buf.data(), 4);
   }

   for(const auto& ip : m_ipv6_addr) {
      // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
      der.add_object(ASN1_Type(7), ASN1_Class::ContextSpecific, ip.address().data(), ip.address().size());
   }

   for(const auto& reg_id : m_registered_ids) {
      // [8] registeredID is IMPLICIT OBJECT IDENTIFIER.
      // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
      der.encode_implicit(reg_id, ASN1_Type(8), ASN1_Class::ContextSpecific);
   }

   der.end_cons();
}

void AlternativeName::decode_from(BER_Decoder& source) {
   BER_Decoder names = source.start_sequence();

   while(names.more_items()) {
      const BER_Object obj = names.get_next_object();

      if(obj.is_a(0, ASN1_Class::ExplicitContextSpecific)) {
         BER_Decoder othername(obj, names.limits());

         OID oid;
         othername.decode(oid);
         const BER_Object othername_value_outer = othername.get_next_object();
         othername.verify_end();

         if(!othername_value_outer.is_a(0, ASN1_Class::ExplicitContextSpecific)) {
            throw Decoding_Error("Invalid tags on otherName value");
         }

         BER_Decoder othername_value_inner(othername_value_outer, names.limits());

         const BER_Object value = othername_value_inner.get_next_object();
         othername_value_inner.verify_end();

         // Capture the inner ANY value verbatim so applications can retrieve
         // it regardless of its ASN.1 form.
         std::vector<uint8_t> raw_value;
         DER_Encoder(raw_value).add_object(value.type_tag(), value.class_tag(), value.data());
         m_other_name_values.insert(OtherNameValue{oid, std::move(raw_value)});

         // Populate old string view for compatibility
         if(ASN1_String::is_string_type(value.type()) && value.get_class() == ASN1_Class::Universal) {
            try {
               m_othernames.insert(std::make_pair(oid, ASN1_String(ASN1::to_string(value), value.type())));
            } catch(const Invalid_Argument&) {  // NOLINT(*-empty-catch)
            }
         }

         if(oid == OID::from_string("PKIX.SmtpUTF8Mailbox")) {
            if(!value.is_a(ASN1_Type::Utf8String, ASN1_Class::Universal)) {
               throw Decoding_Error("SmtpUTF8Mailbox otherName must contain a UTF8String");
            }
            auto parsed_mailbox = SmtpUtf8Mailbox::from_string(ASN1::to_string(value));
            if(!parsed_mailbox.has_value()) {
               throw Decoding_Error("Invalid SmtpUTF8Mailbox encoding");
            }
            m_smtp_utf8_mailboxes.insert(std::move(*parsed_mailbox));
         }
      } else if(obj.is_a(1, ASN1_Class::ContextSpecific)) {
         add_email(ASN1::to_string(obj));
      } else if(obj.is_a(2, ASN1_Class::ContextSpecific)) {
         add_dns(ASN1::to_string(obj));
      } else if(obj.is_a(3, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         // x400Address not supported but it is a SEQUENCE so we know it cannot be empty
         if(obj.length() == 0) {
            throw Decoding_Error("Invalid x400Address field");
         }
      } else if(obj.is_a(4, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         BER_Decoder dec(obj, names.limits());
         X509_DN dn;
         dec.decode(dn).verify_end();
         this->add_dn(dn);
      } else if(obj.is_a(5, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         // ediPartyName not supported but it is a SEQUENCE so we know it cannot be empty
         if(obj.length() == 0) {
            throw Decoding_Error("Invalid ediPartyName field");
         }
      } else if(obj.is_a(6, ASN1_Class::ContextSpecific)) {
         this->add_uri(ASN1::to_string(obj));
      } else if(obj.is_a(7, ASN1_Class::ContextSpecific)) {
         if(obj.length() == 4) {
            const uint32_t ip = load_be<uint32_t>(obj.bits(), 0);
            this->add_ipv4_address(ip);
         } else if(obj.length() == 16) {
            const IPv6Address ip(std::span<const uint8_t, 16>{obj.bits(), 16});
            this->add_ipv6_address(ip);
         } else {
            throw Decoding_Error("Invalid IP constraint neither IPv4 or IPv6");
         }
      } else if(obj.is_a(8, ASN1_Class::ContextSpecific)) {
         // [8] registeredID is IMPLICIT OBJECT IDENTIFIER.
         OID oid;
         names.decode_implicit(obj, oid, ASN1_Type::ObjectId, ASN1_Class::Universal);
         this->add_registered_id(oid);
      } else {
         throw Decoding_Error(fmt("Unknown GeneralName tag {}/class {}",
                                  static_cast<uint32_t>(obj.type_tag()),
                                  static_cast<uint32_t>(obj.class_tag())));
      }
   }
}

}  // namespace Botan
