/*
* ASN.1 OID
* (C) 1999-2007,2024,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/internal/asn1_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/oid_map.h>
#include <botan/internal/parsing.h>
#include <algorithm>
#include <limits>
#include <span>

namespace Botan {

namespace {

/*
* Longest OID encoding we accept. RFC 5280 Appendix B only requires support
* for OIDs of up to 20 arcs each below 2^28, which encode in under 80 bytes.
* An OID carrying a UUID under the 2.25 arc encodes in 20 bytes. Bounding the
* length also bounds the cost of converting an arc to decimal.
*/
constexpr size_t MaxOidEncodingLength = 128;

/*
* Longest subidentifier we accept, in base-128 digits. 19 digits hold 133
* bits, which covers the 128 bit UUIDs embedded under the 2.25 arc.
*/
constexpr size_t MaxSubidentifierLength = 19;

/*
* A subidentifier of 133 bits has at most 41 decimal digits
*/
constexpr size_t MaxArcDecimalDigits = 41;

/*
* Check that the bytes are a valid OID encoding, ie a sequence of
* base-128 subidentifiers each of minimal length
*/
void check_oid_encoding(std::span<const uint8_t> der) {
   if(der.empty()) {
      throw Decoding_Error("OID encoding is too short");
   }

   if(der.size() > MaxOidEncodingLength) {
      throw Decoding_Error("OID encoding is too long");
   }

   size_t subidentifier_len = 0;

   for(const uint8_t b : der) {
      // Even BER requires that the OID have minimal length, ie that
      // the first byte of a multibyte encoding cannot be zero
      // See X.690 section 8.19.2
      if(subidentifier_len == 0 && b == 0x80) {
         throw Decoding_Error("Leading zero byte in multibyte OID encoding");
      }

      subidentifier_len += 1;
      if(subidentifier_len > MaxSubidentifierLength) {
         throw Decoding_Error("OID arc is too large");
      }

      // A clear high bit marks the final byte of the subidentifier
      if((b & 0x80) == 0) {
         subidentifier_len = 0;
      }
   }

   if(subidentifier_len != 0) {
      throw Decoding_Error("Truncated OID value");
   }
}

/*
* Remove and return the leading subidentifier of a valid OID encoding
*/
std::span<const uint8_t> take_subidentifier(std::span<const uint8_t>& der) {
   size_t len = 1;
   while((der[len - 1] & 0x80) == 0x80) {
      ++len;
   }

   const auto subidentifier = der.first(len);
   der = der.subspan(len);
   return subidentifier;
}

/*
* Returns nullopt if the subidentifier does not fit in 64 bits
*/
std::optional<uint64_t> subidentifier_to_u64(std::span<const uint8_t> subidentifier) {
   // A 10 byte subidentifier has 70 bits; it fits only if the leading digit is 1
   if(subidentifier.size() > 10 || (subidentifier.size() == 10 && subidentifier[0] != 0x81)) {
      return std::nullopt;
   }

   uint64_t v = 0;
   for(const uint8_t b : subidentifier) {
      v = (v << 7) | (b & 0x7F);
   }
   return v;
}

void append_subidentifier(std::vector<uint8_t>& der, uint64_t v) {
   size_t digits = 1;
   for(uint64_t t = v >> 7; t > 0; t >>= 7) {
      ++digits;
   }

   for(size_t i = digits; i > 0; --i) {
      const uint64_t digit = (v >> (7 * (i - 1))) & 0x7F;
      der.push_back(static_cast<uint8_t>(digit | (i > 1 ? 0x80 : 0x00)));
   }
}

void append_subidentifier(std::vector<uint8_t>& der, const BigInt& v) {
   const size_t digits = std::max<size_t>(1, (v.bits() + 6) / 7);
   BOTAN_ARG_CHECK(digits <= MaxSubidentifierLength, "OID arc is too large");

   for(size_t i = digits; i > 0; --i) {
      uint8_t digit = 0;
      for(size_t j = 0; j != 7; ++j) {
         digit |= static_cast<uint8_t>(v.get_bit(7 * (i - 1) + j)) << j;
      }
      der.push_back(static_cast<uint8_t>(digit | (i > 1 ? 0x80 : 0x00)));
   }
}

uint64_t root_arc(uint64_t first_subidentifier) {
   if(first_subidentifier < 40) {
      return 0;
   } else if(first_subidentifier < 80) {
      return 1;
   } else {
      return 2;
   }
}

/*
* Call fn(arc) for each arc of a valid OID encoding, stopping early if fn
* returns false. Returns false if it stopped early or if some arc does not
* fit in 64 bits.
*/
template <typename Fn>
bool visit_arcs(std::span<const uint8_t> der, Fn fn) {
   bool first = true;

   while(!der.empty()) {
      const auto subidentifier = subidentifier_to_u64(take_subidentifier(der));
      if(!subidentifier) {
         return false;
      }

      if(first) {
         first = false;
         const uint64_t root = root_arc(*subidentifier);
         if(!fn(root) || !fn(*subidentifier - 40 * root)) {
            return false;
         }
      } else if(!fn(*subidentifier)) {
         return false;
      }
   }

   return true;
}

std::vector<uint8_t> encode_arcs(std::span<const uint32_t> arcs) {
   BOTAN_ARG_CHECK(arcs.size() >= 2, "OID too short to be valid");
   BOTAN_ARG_CHECK(arcs[0] <= 2, "OID root out of range");
   BOTAN_ARG_CHECK(arcs[1] <= 39 || arcs[0] == 2, "OID second arc too large");

   std::vector<uint8_t> der;
   append_subidentifier(der, static_cast<uint64_t>(40) * arcs[0] + arcs[1]);
   for(size_t i = 2; i != arcs.size(); ++i) {
      append_subidentifier(der, arcs[i]);
      BOTAN_ARG_CHECK(der.size() <= MaxOidEncodingLength, "OID encoding is too long");
   }

   return der;
}

/*
* RFC 4512 Section 1.4
*
*    number  = DIGIT / ( LDIGIT 1*DIGIT )
*    numericoid = number 1*( DOT number )
*/
bool is_number(std::string_view s) {
   if(s.empty() || !std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      return false;
   }

   return s.size() == 1 || s[0] != '0';
}

std::vector<uint8_t> encode_oid_string(std::string_view oid_str) {
   std::vector<uint8_t> der;

   std::string_view remaining = oid_str;
   size_t arc_idx = 0;
   uint32_t root = 0;

   for(;;) {
      const size_t dot = remaining.find('.');
      const std::string_view arc = remaining.substr(0, dot);

      if(!is_number(arc)) {
         throw Invalid_Argument(fmt("Could not parse '{}' as an OID", oid_str));
      }

      // Reject arcs which cannot fit before paying for the decimal conversion
      BOTAN_ARG_CHECK(arc.size() <= MaxArcDecimalDigits, "OID arc is too large");

      if(arc_idx == 0) {
         const auto r = parse_u32(arc);
         BOTAN_ARG_CHECK(r.has_value() && *r <= 2, "OID root out of range");
         root = *r;
      } else if(const auto v = parse_u64(arc)) {
         if(arc_idx == 1) {
            BOTAN_ARG_CHECK(*v <= 39 || root == 2, "OID second arc too large");
            if(*v <= std::numeric_limits<uint64_t>::max() - 40 * root) {
               append_subidentifier(der, 40 * root + *v);
            } else {
               BigInt first = BigInt::from_u64(*v);
               first += static_cast<word>(40) * root;
               append_subidentifier(der, first);
            }
         } else {
            append_subidentifier(der, *v);
         }
      } else {
         // A valid number that failed to parse must exceed 64 bits
         BigInt big = BigInt::from_string(arc);
         if(arc_idx == 1) {
            BOTAN_ARG_CHECK(root == 2, "OID second arc too large");
            big += static_cast<word>(80);
         }
         append_subidentifier(der, big);
      }

      BOTAN_ARG_CHECK(der.size() <= MaxOidEncodingLength, "OID encoding is too long");
      ++arc_idx;

      // No more dots implies we just read the last group
      if(dot == std::string_view::npos) {
         break;
      }
      remaining = remaining.substr(dot + 1);
   }

   BOTAN_ARG_CHECK(arc_idx >= 2, "OID too short to be valid");
   return der;
}

}  // namespace

//static
void OID::register_oid(const OID& oid, std::string_view name) {
   OID_Map::global_registry().add_oid(oid, name);
}

//static
std::optional<OID> OID::from_name(std::string_view name) {
   if(name.empty()) {
      throw Invalid_Argument("OID::from_name argument must be non-empty");
   }

   OID o = OID_Map::global_registry().str2oid(name);
   if(o.has_value()) {
      return std::optional(o);
   }

   return std::nullopt;
}

//static
OID OID::from_string(std::string_view str) {
   if(str.empty()) {
      throw Invalid_Argument("OID::from_string argument must be non-empty");
   }

   OID o = OID_Map::global_registry().str2oid(str);
   if(o.has_value()) {
      return o;
   }

   // Try to parse as a dotted decimal
   try {
      return OID(str);
   } catch(...) {}

   throw Lookup_Error(fmt("No OID associated with name '{}'", str));
}

//static
OID OID::from_der_contents(std::span<const uint8_t> contents) {
   check_oid_encoding(contents);
   OID oid;
   oid.m_der.assign(contents.begin(), contents.end());
   return oid;
}

OID::OID(std::initializer_list<uint32_t> init) : OID(std::span(init.begin(), init.size())) {}

OID::OID(std::span<const uint32_t> init) : m_der(encode_arcs(init)) {}

/*
* ASN.1 OID Constructor
*/
OID::OID(std::string_view oid_str) : m_der(encode_oid_string(oid_str)) {}

/*
* Return this OID as a string
*/
std::string OID::to_string() const {
   std::string out;

   std::span<const uint8_t> der(m_der);
   bool first = true;

   auto subidentifier_to_bigint = [](std::span<const uint8_t> subidentifier) -> BigInt {
      BigInt v;
      for(const uint8_t b : subidentifier) {
         v <<= 7;
         v += static_cast<word>(b & 0x7F);
      }
      return v;
   };

   while(!der.empty()) {
      const auto subidentifier = take_subidentifier(der);

      if(!first) {
         out.push_back('.');
      }

      // avoid locale issues with integer formatting
      if(const auto v = subidentifier_to_u64(subidentifier)) {
         if(first) {
            const uint64_t root = root_arc(*v);
            out += std::to_string(root);
            out.push_back('.');
            out += std::to_string(*v - 40 * root);
         } else {
            out += std::to_string(*v);
         }
      } else {
         BigInt big = subidentifier_to_bigint(subidentifier);
         if(first) {
            out += "2.";
            big -= static_cast<word>(80);
         }
         out += big.to_dec_string();
      }

      first = false;
   }

   return out;
}

std::string OID::to_formatted_string() const {
   if(auto name = this->registered_name()) {
      return *name;
   } else {
      return this->to_string();
   }
}

std::string OID::human_name_or_empty() const {
   return this->registered_name().value_or("");
}

std::optional<std::string> OID::registered_name() const {
   return OID_Map::global_registry().oid2str(*this);
}

bool OID::registered_oid() const {
   return this->registered_name().has_value();
}

bool OID::matches(std::initializer_list<uint32_t> other) const {
   const auto* it = other.begin();

   const bool all_match = visit_arcs(m_der, [&](uint64_t arc) {
      if(it == other.end() || *it != arc) {
         return false;
      }
      ++it;
      return true;
   });

   return all_match && it == other.end();
}

uint64_t OID::hash_code() const {
   // FNV-1a over the encoding
   // If this is changed also update gen_oids.py to match
   uint64_t hash = 0xCBF29CE484222325;
   for(const uint8_t b : m_der) {
      hash ^= b;
      hash *= 0x100000001B3;
   }
   return hash;
}

/*
* DER encode an OBJECT IDENTIFIER
*/
void OID::encode_into(DER_Encoder& der) const {
   if(m_der.empty()) {
      throw Invalid_Argument("OID::encode_into: OID is invalid");
   }

   der.add_object(ASN1_Type::ObjectId, ASN1_Class::Universal, m_der);
}

/*
* Decode a BER encoded OBJECT IDENTIFIER
*/
void OID::decode_from(BER_Decoder& decoder) {
   const BER_Object obj = decoder.get_next_object();
   if(obj.tagging() != (ASN1_Class::Universal | ASN1_Type::ObjectId)) {
      throw BER_Bad_Tag("Error decoding OID, unknown tag", obj.tagging());
   }

   check_oid_encoding(obj.data());
   m_der.assign(obj.data().begin(), obj.data().end());
}

std::ostream& operator<<(std::ostream& out, const OID& oid) {
   out << oid.to_string();
   return out;
}

std::optional<uint32_t> ASN1::is_sub_element_of(const OID& oid, std::initializer_list<uint32_t> prefix) {
   const auto* it = prefix.begin();
   std::optional<uint32_t> last_arc;

   const bool ok = visit_arcs(oid.der_contents(), [&](uint64_t arc) {
      if(it != prefix.end()) {
         if(*it != arc) {
            return false;
         }
         ++it;
         return true;
      }

      // Exactly one arc beyond the prefix is allowed, and it must fit in 32 bits
      if(last_arc.has_value() || arc > std::numeric_limits<uint32_t>::max()) {
         return false;
      }

      last_arc = static_cast<uint32_t>(arc);
      return true;
   });

   if(ok && it == prefix.end()) {
      return last_arc;
   }

   return std::nullopt;
}

}  // namespace Botan
