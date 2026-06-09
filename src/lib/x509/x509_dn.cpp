/*
* X509_DN
* (C) 1999-2007,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/charset.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/x509_utils.h>
#include <algorithm>
#include <istream>
#include <iterator>
#include <optional>
#include <ostream>
#include <sstream>

namespace Botan {

namespace {

bool is_space(char c) {
   return c == ' ' || c == '\t';
}

std::optional<uint8_t> hex_digit_value(char c) {
   if(c >= '0' && c <= '9') {
      return static_cast<uint8_t>(c - '0');
   } else if(c >= 'a' && c <= 'f') {
      return static_cast<uint8_t>(c - 'a' + 10);
   } else if(c >= 'A' && c <= 'F') {
      return static_cast<uint8_t>(c - 'A' + 10);
   } else {
      return {};
   }
}

/*
* RFC 4514 Section 3 specifies which characters can be escaped
*/
bool is_escapable_char(char c) {
   switch(c) {
      case '\\':
      case '"':
      case '+':
      case ',':
      case ';':
      case '<':
      case '>':
      case ' ':
      case '#':
      case '=':
         return true;
      default:
         return false;
   }
}

bool is_unescaped_special_value_char(char c) {
   switch(c) {
      case ';':
      case '<':
      case '>':
      case '#':
      case '=':
         return true;
      default:
         return false;
   }
}

/*
* Yields the X.500 canonical form of a name component one character at a time
*/
class X500_Char_Iterator final {
   public:
      explicit X500_Char_Iterator(std::string_view s) : m_str(s), m_pos(0) {
         // Skip leading whitespace
         while(m_pos < m_str.size() && is_space(m_str[m_pos])) {
            ++m_pos;
         }
      }

      // Returns next canonical character, or nullopt when exhausted.
      std::optional<char> next() {
         if(m_pos >= m_str.size()) {
            return std::nullopt;
         }

         if(is_space(m_str[m_pos])) {
            // Skip the entire whitespace run
            while(m_pos < m_str.size() && is_space(m_str[m_pos])) {
               ++m_pos;
            }
            // Emit a single space only if more content follows (strip trailing ws)
            if(m_pos < m_str.size()) {
               return ' ';
            }
            return std::nullopt;
         }

         const char c = m_str[m_pos++];
         // Locale-independent ASCII fold; RFC 5280 DN matching does not depend on libc locale
         if(c >= 'A' && c <= 'Z') {
            return static_cast<char>(c + ('a' - 'A'));
         }
         return c;
      }

      static std::string canonicalize(std::string_view name) {
         std::string result;
         result.reserve(name.size());

         X500_Char_Iterator it(name);
         while(auto c = it.next()) {
            result += *c;
         }

         return result;
      }

   private:
      std::string_view m_str;
      size_t m_pos;
};

}  // namespace

/*
* Add an attribute to a X509_DN
*/
void X509_DN::add_attribute(std::string_view type, std::string_view str) {
   add_attribute(OID::from_string(type), str);
}

/*
* Add an attribute to a X509_DN
*/
void X509_DN::add_attribute(const OID& oid, const ASN1_String& str) {
   if(str.empty()) {
      return;
   }

   // Each programmatic add appends a new single-AVA RDN.
   m_rdn.push_back({std::make_pair(oid, str)});
   m_dn_bits.clear();
   update_canonical_bits();
}

void X509_DN::add_rdn(std::vector<std::pair<OID, ASN1_String>> rdn) {
   if(rdn.empty()) {
      return;
   }
   m_rdn.push_back(std::move(rdn));
   m_dn_bits.clear();
   update_canonical_bits();
}

std::vector<std::pair<OID, ASN1_String>> X509_DN::dn_info() const {
   std::vector<std::pair<OID, ASN1_String>> flat;
   for(const auto& rdn : m_rdn) {
      for(const auto& ava : rdn) {
         flat.push_back(ava);
      }
   }
   return flat;
}

/*
* Get the attributes of this X509_DN
*/
std::multimap<OID, std::string> X509_DN::get_attributes() const {
   std::multimap<OID, std::string> retval;

   for(const auto& rdn : m_rdn) {
      for(const auto& ava : rdn) {
         retval.emplace(ava.first, ava.second.value());
      }
   }
   return retval;
}

/*
* Get the contents of this X.500 Name
*/
std::multimap<std::string, std::string> X509_DN::contents() const {
   std::multimap<std::string, std::string> retval;

   for(const auto& rdn : m_rdn) {
      for(const auto& ava : rdn) {
         retval.emplace(ava.first.to_formatted_string(), ava.second.value());
      }
   }
   return retval;
}

bool X509_DN::has_field(std::string_view attr) const {
   try {
      const OID o = OID::from_string(deref_info_field(attr));
      if(o.has_value()) {
         return has_field(o);
      }
   } catch(Lookup_Error&) {}

   return false;
}

bool X509_DN::has_field(const OID& oid) const {
   for(const auto& rdn : m_rdn) {
      for(const auto& ava : rdn) {
         if(ava.first == oid) {
            return true;
         }
      }
   }

   return false;
}

std::string X509_DN::get_first_attribute(std::string_view attr) const {
   const OID oid = OID::from_string(deref_info_field(attr));
   return get_first_attribute(oid).value();
}

ASN1_String X509_DN::get_first_attribute(const OID& oid) const {
   for(const auto& rdn : m_rdn) {
      for(const auto& ava : rdn) {
         if(ava.first == oid) {
            return ava.second;
         }
      }
   }

   return ASN1_String();
}

/*
* Get a single attribute type
*/
std::vector<std::string> X509_DN::get_attribute(std::string_view attr) const {
   const OID oid = OID::from_string(deref_info_field(attr));

   std::vector<std::string> values;

   for(const auto& rdn : m_rdn) {
      for(const auto& ava : rdn) {
         if(ava.first == oid) {
            values.push_back(ava.second.value());
         }
      }
   }

   return values;
}

/*
* Deref aliases in a subject/issuer info request
*/
std::string X509_DN::deref_info_field(std::string_view info) {
   if(info == "Name" || info == "CommonName" || info == "CN") {
      return "X520.CommonName";
   }
   if(info == "SerialNumber" || info == "SN") {
      return "X520.SerialNumber";
   }
   if(info == "Country" || info == "C") {
      return "X520.Country";
   }
   if(info == "Organization" || info == "O") {
      return "X520.Organization";
   }
   if(info == "Organizational Unit" || info == "OrgUnit" || info == "OU") {
      return "X520.OrganizationalUnit";
   }
   if(info == "Locality" || info == "L") {
      return "X520.Locality";
   }
   if(info == "State" || info == "Province" || info == "ST") {
      return "X520.State";
   }
   if(info == "Email") {
      return "RFC822";
   }
   return std::string(info);
}

namespace {

/*
* Canonical form of an RDN's AVAs: each value is X.500-canonicalized
* (case-fold and whitespace collapse) and the resulting (OID, value)
* pairs are sorted, so an RDN's SET semantics reduce to vector equality.
*/
std::vector<std::pair<OID, std::string>> canonicalize_rdn(const std::vector<std::pair<OID, ASN1_String>>& rdn) {
   std::vector<std::pair<OID, std::string>> result;
   result.reserve(rdn.size());
   for(const auto& ava : rdn) {
      result.emplace_back(ava.first, X500_Char_Iterator::canonicalize(ava.second.value()));
   }
   if(result.size() != 1) {
      std::sort(result.begin(), result.end());
   }
   return result;
}

std::vector<uint8_t> canonicalize_dn(const std::vector<std::vector<std::pair<OID, ASN1_String>>>& rdns) {
   auto append_canonical_data = []<typename T>(std::vector<uint8_t>& out, const T& data) {
      const std::array<uint8_t, 8> data_len = store_le(static_cast<uint64_t>(data.size()));
      out.insert(out.end(), data_len.begin(), data_len.end());
      out.insert(out.end(), data.begin(), data.end());
   };

   std::vector<uint8_t> canonical_bits;

   for(const auto& rdn : rdns) {
      std::vector<uint8_t> rdn_bits;

      for(const auto& [oid, value] : canonicalize_rdn(rdn)) {
         append_canonical_data(rdn_bits, oid.BER_encode());
         append_canonical_data(rdn_bits, value);
      }

      append_canonical_data(canonical_bits, rdn_bits);
   }

   return canonical_bits;
}

}  // namespace

/*
* Compare two X509_DNs for equality
*/
bool operator==(const X509_DN& dn1, const X509_DN& dn2) {
   return dn1._canonical_bytes() == dn2._canonical_bytes();
}

/*
* Compare two X509_DNs for inequality
*/
bool operator!=(const X509_DN& dn1, const X509_DN& dn2) {
   return !(dn1 == dn2);
}

/*
* Induce an arbitrary ordering on DNs that respects RDN sequence order
* and RDN set-equality.
*/
bool operator<(const X509_DN& dn1, const X509_DN& dn2) {
   return dn1._canonical_bytes() < dn2._canonical_bytes();
}

bool x509_dn_subtree_match(const X509_DN& name, const X509_DN& constraint) {
   const auto& name_bits = name._canonical_bytes();
   const auto& constraint_bits = constraint._canonical_bytes();

   if(constraint_bits.size() > name_bits.size()) {
      return false;
   }

   return std::equal(constraint_bits.begin(), constraint_bits.end(), name_bits.begin());
}

void X509_DN::update_canonical_bits() {
   m_canonical_dn_bits = canonicalize_dn(m_rdn);
}

std::vector<uint8_t> X509_DN::DER_encode() const {
   std::vector<uint8_t> result;
   DER_Encoder der(result);
   this->encode_into(der);
   return result;
}

/*
* DER encode a DistinguishedName
*/
void X509_DN::encode_into(DER_Encoder& der) const {
   der.start_sequence();

   if(!m_dn_bits.empty()) {
      /*
      If we decoded this from somewhere, encode it back exactly as
      we received it
      */
      der.raw_bytes(m_dn_bits);
   } else {
      for(const auto& rdn : m_rdn) {
         der.start_set();
         for(const auto& ava : rdn) {
            der.start_sequence().encode(ava.first).encode(ava.second).end_cons();
         }
         der.end_cons();
      }
   }

   der.end_cons();
}

/*
* Decode a BER encoded DistinguishedName
*/
void X509_DN::decode_from(BER_Decoder& source) {
   std::vector<uint8_t> bits;

   source.start_sequence().raw_bytes(bits).end_cons();

   BER_Decoder sequence(bits, source.limits());

   std::vector<std::vector<std::pair<OID, ASN1_String>>> rdns;

   // Cap AVAs per RDN to bound work for downstream set-based matching.
   // No legitimate cert has anywhere near this many AVAs in a single RDN.
   constexpr size_t MAX_AVAS_PER_RDN = 32;

   while(sequence.more_items()) {
      BER_Decoder rdn_decoder = sequence.start_set();

      std::vector<std::pair<OID, ASN1_String>> rdn;
      while(rdn_decoder.more_items()) {
         OID oid;
         ASN1_String str;

         rdn_decoder.start_sequence()
            .decode(oid)
            .decode(str)  // TODO support Any
            .end_cons();

         rdn.emplace_back(std::move(oid), std::move(str));

         if(rdn.size() > MAX_AVAS_PER_RDN) {
            throw Decoding_Error("X.500 RDN has too many attribute-value assertions");
         }
      }

      /*
      RFC 5280 4.1.2.4:
         RelativeDistinguishedName ::=
           SET SIZE (1..MAX) OF AttributeTypeAndValue
      */
      if(rdn.empty()) {
         throw Decoding_Error("X.500 RDN must contain at least one attribute-value assertion");
      }
      rdns.push_back(std::move(rdn));
   }

   auto canonical_bits = canonicalize_dn(rdns);

   m_rdn = std::move(rdns);
   m_dn_bits = std::move(bits);
   m_canonical_dn_bits = std::move(canonical_bits);
}

namespace {

std::string to_short_form(const OID& oid) {
   std::string long_id = oid.to_formatted_string();

   if(long_id == "X520.CommonName") {
      return "CN";
   }

   if(long_id == "X520.Country") {
      return "C";
   }

   if(long_id == "X520.Organization") {
      return "O";
   }

   if(long_id == "X520.OrganizationalUnit") {
      return "OU";
   }

   return long_id;
}

}  // namespace

std::string X509_DN::to_string() const {
   std::ostringstream out;
   out << *this;
   return out.str();
}

std::ostream& operator<<(std::ostream& out, const X509_DN& dn) {
   const auto& rdns = dn.rdns();

   // Escape characters as a backslash plus two hex digits per byte
   // See RFC 4514 Sections 2.4 and 4
   auto hex_escape = [](std::ostream& s, char c) {
      const auto b = static_cast<uint8_t>(c);
      s << '\\' << nibble_to_hex(b >> 4) << nibble_to_hex(b);
   };

   // AVAs within the same RDN are joined with '+' (per RFC 4514), so a
   // multi-valued RDN remains distinguishable from multiple single-valued
   // RDNs separated by ','.
   bool first_rdn = true;
   for(const auto& rdn : rdns) {
      if(!first_rdn) {
         out << ",";
      }
      first_rdn = false;

      bool first_ava = true;
      for(const auto& ava : rdn) {
         if(!first_ava) {
            out << "+";
         }
         first_ava = false;
         out << to_short_form(ava.first) << "=\"";
         const std::string_view value = ava.second.value();
         size_t pos = 0;
         while(pos < value.size()) {
            const size_t start = pos;

            uint32_t cp = 0;
            try {
               cp = next_utf8_codepoint(value, pos);
            } catch(const Decoding_Error&) {
               // value() should always be valid UTF-8, but escape defensively otherwise
               hex_escape(out, value[start]);
               pos = start + 1;
               continue;
            }

            if(cp == '\\' || cp == '"') {
               out << '\\' << static_cast<char>(cp);
            } else if(is_unicode_control_char(cp)) {
               for(size_t i = start; i < pos; ++i) {
                  hex_escape(out, value[i]);
               }
            } else {
               out << value.substr(start, pos - start);
            }
         }
         out << "\"";
      }
   }
   return out;
}

/*
* Parse the string representation of a distinguished name, accepting
* the formats specified in RFC 4514 Section 3 as well as RFC 2253's
* quoted format.
*/
std::optional<X509_DN> X509_DN::parse(std::string_view str) {
   X509_DN dn;

   // AVAs accumulate here; a trailing '+' keeps the next AVA in the same
   // RDN, while a ',' (or end of input) flushes them as a single RDN.
   std::vector<std::pair<OID, ASN1_String>> pending_rdn;

   // Separator that ended the previous AVA. A ',' or '+' still pending after the
   // loop means the input ended with a separator and no AVA to follow it.
   char terminator = '\0';

   size_t pos = 0;
   while(pos < str.size()) {
      // Whitespace separating an attributeType from the preceding ',' or '+'
      // is tolerated even though RFC 4514 does not produce it.
      while(pos < str.size() && is_space(str[pos])) {
         ++pos;
      }
      if(pos == str.size()) {
         break;
      }

      // attributeType, terminated by '='
      const size_t type_start = pos;
      while(pos < str.size() && str[pos] != '=' && !is_space(str[pos])) {
         ++pos;
      }
      const std::string_view type = str.substr(type_start, pos - type_start);
      if(type.empty() || pos == str.size() || str[pos] != '=') {
         return std::nullopt;
      }
      ++pos;  // consume '='

      /*
      attributeValue, in RFC 4514 <string> form plus the legacy quoted form.
      value_len tracks the length up to the last significant octet: leading and
      trailing unescaped whitespace is not significant unless it was escaped or
      quoted, so trailing whitespace is dropped by the final resize.
      */
      std::string value;
      size_t value_len = 0;

      // The legacy quoted form wraps the whole value: a quote is only an opening
      // quote at the start of the value, and nothing but trailing whitespace or a
      // separator may follow the closing quote.
      enum class Quote : uint8_t { None, Open, Closed };
      Quote quote = Quote::None;

      terminator = '\0';

      while(pos < str.size()) {
         const char c = str[pos];

         if(c == '"') {
            if(quote == Quote::Open) {
               quote = Quote::Closed;
            } else if(quote == Quote::None && value.empty()) {
               quote = Quote::Open;
            } else {
               return std::nullopt;  // quote in mid-value or after the closing quote
            }
            ++pos;
         } else if(c == '\\') {
            if(quote == Quote::Closed) {
               return std::nullopt;  // escape after the closing quote
            }
            // pair = ESC ( ESC / special / hexpair )
            ++pos;
            if(pos == str.size()) {
               return std::nullopt;
            }
            if(const auto hi = hex_digit_value(str[pos])) {
               const auto lo = (pos + 1 < str.size()) ? hex_digit_value(str[pos + 1]) : std::nullopt;
               if(!lo) {
                  return std::nullopt;
               }
               value.push_back(static_cast<char>((*hi << 4) | *lo));
               pos += 2;
            } else if(is_escapable_char(str[pos])) {
               value.push_back(str[pos]);
               ++pos;
            } else {
               return std::nullopt;  // not ESC / special / hexpair
            }
            value_len = value.size();  // an escaped octet is always significant
         } else if((c == ',' || c == '+') && quote != Quote::Open) {
            terminator = c;
            ++pos;
            break;
         } else if(quote == Quote::Closed) {
            if(!is_space(c)) {
               return std::nullopt;  // content after the closing quote
            }
            ++pos;  // trailing whitespace after the closing quote is insignificant
         } else if(quote != Quote::Open && is_unescaped_special_value_char(c)) {
            return std::nullopt;
         } else {
            ++pos;
            if(is_space(c) && quote != Quote::Open) {
               // Keep interior whitespace only if more content follows; skip it
               // entirely while leading (value is still empty)
               if(!value.empty()) {
                  value.push_back(c);
               }
            } else {
               value.push_back(c);
               value_len = value.size();
            }
         }
      }

      if(quote == Quote::Open) {
         return std::nullopt;  // unterminated quoted value
      }
      value.resize(value_len);  // strip trailing unescaped whitespace

      try {
         OID oid = OID::from_string(deref_info_field(type));
         // ASN1_String rejects values (e.g. a \FF hexpair) that are not valid
         // for any supported string encoding.
         pending_rdn.emplace_back(std::move(oid), ASN1_String(value));
      } catch(const Exception&) {
         return std::nullopt;  // unknown attributeType or invalid attributeValue
      }

      if(terminator != '+') {
         dn.add_rdn(std::move(pending_rdn));
         pending_rdn.clear();
      }
   }

   // A trailing ',' or '+' leaves an RDN/AVA with nothing to follow it
   if(terminator == ',' || terminator == '+') {
      return std::nullopt;
   }
   return dn;
}

std::istream& operator>>(std::istream& in, X509_DN& dn) {
   const std::istreambuf_iterator<char> begin(in);
   const std::istreambuf_iterator<char> end;
   const std::string contents(begin, end);

   if(auto parsed = X509_DN::parse(contents)) {
      dn = std::move(*parsed);
   } else {
      in.setstate(std::ios::failbit);
   }
   return in;
}
}  // namespace Botan
