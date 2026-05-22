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
#include <botan/internal/x509_utils.h>
#include <algorithm>
#include <ostream>
#include <sstream>

namespace Botan {

namespace {

bool is_space(char c) {
   return c == ' ' || c == '\t';
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

std::string x500_canonicalize_value(std::string_view name) {
   return X500_Char_Iterator::canonicalize(name);
}

bool x500_name_cmp(std::string_view name1, std::string_view name2) {
   X500_Char_Iterator it1(name1);
   X500_Char_Iterator it2(name2);

   while(true) {
      const auto c1 = it1.next();
      const auto c2 = it2.next();

      if(c1 != c2) {
         return false;
      }
      if(!c1.has_value() && !c2.has_value()) {
         return true;
      }
   }
}

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
}

void X509_DN::add_rdn(std::vector<std::pair<OID, ASN1_String>> rdn) {
   if(rdn.empty()) {
      return;
   }
   m_rdn.push_back(std::move(rdn));
   m_dn_bits.clear();
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
      result.emplace_back(ava.first, x500_canonicalize_value(ava.second.value()));
   }
   std::sort(result.begin(), result.end());
   return result;
}

}  // namespace

bool rdn_equality(const std::vector<std::pair<OID, ASN1_String>>& a,
                  const std::vector<std::pair<OID, ASN1_String>>& b) {
   if(a.size() != b.size()) {
      return false;
   }

   // Single-AVA RDN is the overwhelmingly common case.
   if(a.size() == 1) {
      return a[0].first == b[0].first && x500_name_cmp(a[0].second.value(), b[0].second.value());
   }

   return canonicalize_rdn(a) == canonicalize_rdn(b);
}

/*
* Compare two X509_DNs for equality
*/
bool operator==(const X509_DN& dn1, const X509_DN& dn2) {
   const auto& r1 = dn1.rdns();
   const auto& r2 = dn2.rdns();

   if(r1.size() != r2.size()) {
      return false;
   }

   for(size_t i = 0; i < r1.size(); ++i) {
      if(!rdn_equality(r1[i], r2[i])) {
         return false;
      }
   }

   return true;
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
   const auto& r1 = dn1.rdns();
   const auto& r2 = dn2.rdns();

   if(r1.size() != r2.size()) {
      return r1.size() < r2.size();
   }

   for(size_t i = 0; i < r1.size(); ++i) {
      if(r1[i].size() != r2[i].size()) {
         return r1[i].size() < r2[i].size();
      }

      if(r1[i].size() == 1) {
         if(r1[i][0].first != r2[i][0].first) {
            return r1[i][0].first < r2[i][0].first;
         }
         const auto c1 = x500_canonicalize_value(r1[i][0].second.value());
         const auto c2 = x500_canonicalize_value(r2[i][0].second.value());
         if(c1 != c2) {
            return c1 < c2;
         }
         continue;
      }

      const auto c1 = canonicalize_rdn(r1[i]);
      const auto c2 = canonicalize_rdn(r2[i]);
      if(c1 != c2) {
         return c1 < c2;
      }
   }

   BOTAN_DEBUG_ASSERT(dn1 == dn2);
   return false;
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

   m_rdn.clear();

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
      m_rdn.push_back(std::move(rdn));
   }

   m_dn_bits = bits;
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
         for(const char c : ava.second.value()) {
            if(c == '\\' || c == '\"') {
               out << "\\";
            }
            out << c;
         }
         out << "\"";
      }
   }
   return out;
}

std::istream& operator>>(std::istream& in, X509_DN& dn) {
   in >> std::noskipws;

   // AVAs are buffered until we hit a ',' (or EOF), at which point they
   // are flushed as a single RDN. A '+' between AVAs keeps them in the
   // same RDN, matching the output of operator<<.
   std::vector<std::pair<OID, ASN1_String>> pending_rdn;

   // NOLINTNEXTLINE(*-avoid-do-while)
   do {
      std::string key;
      std::string val;
      char c = 0;

      while(in.good()) {
         in >> c;

         if(is_space(c) && key.empty()) {
            continue;
         } else if(!is_space(c)) {
            key.push_back(c);
            break;
         } else {
            break;
         }
      }

      while(in.good()) {
         in >> c;

         if(!is_space(c) && c != '=') {
            key.push_back(c);
         } else if(c == '=') {
            break;
         } else {
            throw Invalid_Argument("Ill-formed X.509 DN");
         }
      }

      bool in_quotes = false;
      char terminator = '\0';
      while(in.good()) {
         in >> c;

         if(is_space(c)) {
            if(!in_quotes && !val.empty()) {
               break;
            } else if(in_quotes) {
               val.push_back(' ');
            }
         } else if(c == '"') {
            in_quotes = !in_quotes;
         } else if(c == '\\') {
            if(in.good()) {
               in >> c;
            }
            val.push_back(c);
         } else if((c == ',' || c == '+') && !in_quotes) {
            terminator = c;
            break;
         } else {
            val.push_back(c);
         }
      }

      if(!key.empty() && !val.empty()) {
         const OID oid = OID::from_string(X509_DN::deref_info_field(key));
         pending_rdn.emplace_back(oid, ASN1_String(val));
         if(terminator != '+') {
            dn.add_rdn(std::move(pending_rdn));
            pending_rdn.clear();
         }
      } else {
         break;
      }
   } while(in.good());

   dn.add_rdn(std::move(pending_rdn));
   return in;
}
}  // namespace Botan
