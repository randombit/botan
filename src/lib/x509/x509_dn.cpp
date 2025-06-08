/*
* X509_DN
* (C) 1999-2007,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/stl_util.h>
#include <cctype>
#include <ostream>
#include <sstream>

namespace Botan {

namespace {

namespace {

bool caseless_cmp(char a, char b) {
   return (std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)));
}

bool is_space(char c) {
   return std::isspace(static_cast<unsigned char>(c));
}

}  // namespace

/*
* X.500 String Comparison
*/
bool x500_name_cmp(std::string_view name1, std::string_view name2) {
   auto p1 = name1.begin();
   auto p2 = name2.begin();

   while((p1 != name1.end()) && is_space(*p1)) {
      ++p1;
   }
   while((p2 != name2.end()) && is_space(*p2)) {
      ++p2;
   }

   while(p1 != name1.end() && p2 != name2.end()) {
      if(is_space(*p1)) {
         if(!is_space(*p2)) {
            return false;
         }

         while((p1 != name1.end()) && is_space(*p1)) {
            ++p1;
         }
         while((p2 != name2.end()) && is_space(*p2)) {
            ++p2;
         }

         if(p1 == name1.end() && p2 == name2.end()) {
            return true;
         }
         if(p1 == name1.end() || p2 == name2.end()) {
            return false;
         }
      }

      if(!caseless_cmp(*p1, *p2)) {
         return false;
      }
      ++p1;
      ++p2;
   }

   while((p1 != name1.end()) && is_space(*p1)) {
      ++p1;
   }
   while((p2 != name2.end()) && is_space(*p2)) {
      ++p2;
   }

   if((p1 != name1.end()) || (p2 != name2.end())) {
      return false;
   }
   return true;
}

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

   m_rdn.push_back(std::make_pair(oid, str));
   m_dn_bits.clear();
}

/*
* Get the attributes of this X509_DN
*/
std::multimap<OID, std::string> X509_DN::get_attributes() const {
   std::multimap<OID, std::string> retval;

   for(auto& i : m_rdn) {
      retval.emplace(i.first, i.second.value());
   }
   return retval;
}

/*
* Get the contents of this X.500 Name
*/
std::multimap<std::string, std::string> X509_DN::contents() const {
   std::multimap<std::string, std::string> retval;

   for(auto& i : m_rdn) {
      retval.emplace(i.first.to_formatted_string(), i.second.value());
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
   for(auto& i : m_rdn) {
      if(i.first == oid) {
         return true;
      }
   }

   return false;
}

std::string X509_DN::get_first_attribute(std::string_view attr) const {
   const OID oid = OID::from_string(deref_info_field(attr));
   return get_first_attribute(oid).value();
}

ASN1_String X509_DN::get_first_attribute(const OID& oid) const {
   for(auto& i : m_rdn) {
      if(i.first == oid) {
         return i.second;
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

   for(auto& i : m_rdn) {
      if(i.first == oid) {
         values.push_back(i.second.value());
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

/*
* Compare two X509_DNs for equality
*/
bool operator==(const X509_DN& dn1, const X509_DN& dn2) {
   auto attr1 = dn1.get_attributes();
   auto attr2 = dn2.get_attributes();

   if(attr1.size() != attr2.size()) {
      return false;
   }

   auto p1 = attr1.begin();
   auto p2 = attr2.begin();

   while(true) {
      if(p1 == attr1.end() && p2 == attr2.end()) {
         break;
      }
      if(p1 == attr1.end()) {
         return false;
      }
      if(p2 == attr2.end()) {
         return false;
      }
      if(p1->first != p2->first) {
         return false;
      }
      if(!x500_name_cmp(p1->second, p2->second)) {
         return false;
      }
      ++p1;
      ++p2;
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
* Induce an arbitrary ordering on DNs
*/
bool operator<(const X509_DN& dn1, const X509_DN& dn2) {
   auto attr1 = dn1.get_attributes();
   auto attr2 = dn2.get_attributes();

   // If they are not the same size, choose the smaller as the "lessor"
   if(attr1.size() < attr2.size()) {
      return true;
   }
   if(attr1.size() > attr2.size()) {
      return false;
   }

   // We know they are the same # of elements, now compare the OIDs:
   auto p1 = attr1.begin();
   auto p2 = attr2.begin();

   while(p1 != attr1.end() && p2 != attr2.end()) {
      if(p1->first != p2->first) {
         return (p1->first < p2->first);
      }

      ++p1;
      ++p2;
   }

   // We know this is true because maps have the same size
   BOTAN_ASSERT_NOMSG(p1 == attr1.end());
   BOTAN_ASSERT_NOMSG(p2 == attr2.end());

   // Now we know all elements have the same OIDs, compare
   // their string values:

   p1 = attr1.begin();
   p2 = attr2.begin();
   while(p1 != attr1.end() && p2 != attr2.end()) {
      BOTAN_DEBUG_ASSERT(p1->first == p2->first);

      // They may be binary different but same by X.500 rules, check this
      if(!x500_name_cmp(p1->second, p2->second)) {
         // If they are not (by X.500) the same string, pick the
         // lexicographic first as the lessor
         return (p1->second < p2->second);
      }

      ++p1;
      ++p2;
   }

   // if we reach here, then the DNs should be identical
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
      for(const auto& dn : m_rdn) {
         der.start_set().start_sequence().encode(dn.first).encode(dn.second).end_cons().end_cons();
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

   BER_Decoder sequence(bits);

   m_rdn.clear();

   while(sequence.more_items()) {
      BER_Decoder rdn = sequence.start_set();

      while(rdn.more_items()) {
         OID oid;
         ASN1_String str;

         rdn.start_sequence()
            .decode(oid)
            .decode(str)  // TODO support Any
            .end_cons();

         add_attribute(oid, str);
      }
   }

   // Have to assign last as add_attribute zaps m_dn_bits
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
   const auto& info = dn.dn_info();

   for(size_t i = 0; i != info.size(); ++i) {
      out << to_short_form(info[i].first) << "=\"";
      for(char c : info[i].second.value()) {
         if(c == '\\' || c == '\"') {
            out << "\\";
         }
         out << c;
      }
      out << "\"";

      if(i + 1 < info.size()) {
         out << ",";
      }
   }
   return out;
}

std::istream& operator>>(std::istream& in, X509_DN& dn) {
   in >> std::noskipws;
   do {
      std::string key;
      std::string val;
      char c;

      while(in.good()) {
         in >> c;

         if(std::isspace(c) && key.empty()) {
            continue;
         } else if(!std::isspace(c)) {
            key.push_back(c);
            break;
         } else {
            break;
         }
      }

      while(in.good()) {
         in >> c;

         if(!std::isspace(c) && c != '=') {
            key.push_back(c);
         } else if(c == '=') {
            break;
         } else {
            throw Invalid_Argument("Ill-formed X.509 DN");
         }
      }

      bool in_quotes = false;
      while(in.good()) {
         in >> c;

         if(std::isspace(c)) {
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
         } else if(c == ',' && !in_quotes) {
            break;
         } else {
            val.push_back(c);
         }
      }

      if(!key.empty() && !val.empty()) {
         dn.add_attribute(X509_DN::deref_info_field(key), val);
      } else {
         break;
      }
   } while(in.good());
   return in;
}
}  // namespace Botan
