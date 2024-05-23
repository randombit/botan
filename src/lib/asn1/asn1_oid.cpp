/*
* ASN.1 OID
* (C) 1999-2007,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/oid_map.h>
#include <botan/internal/parsing.h>
#include <botan/internal/stl_util.h>
#include <algorithm>
#include <span>
#include <sstream>

namespace Botan {

namespace {

void oid_valid_check(std::span<const uint32_t> oid) {
   BOTAN_ARG_CHECK(oid.size() >= 2, "OID too short to be valid");
   BOTAN_ARG_CHECK(oid[0] <= 2, "OID root out of range");
   BOTAN_ARG_CHECK(oid[1] <= 39 || oid[0] == 2, "OID second arc too large");
   // This last is a limitation of using 32 bit integers when decoding
   // not a limitation of ASN.1 object identifiers in general
   BOTAN_ARG_CHECK(oid[1] <= 0xFFFFFFAF, "OID second arc too large");
}

// returns empty on invalid
std::vector<uint32_t> parse_oid_str(std::string_view oid) {
   try {
      std::string elem;
      std::vector<uint32_t> oid_elems;

      for(char c : oid) {
         if(c == '.') {
            if(elem.empty()) {
               return std::vector<uint32_t>();
            }
            oid_elems.push_back(to_u32bit(elem));
            elem.clear();
         } else {
            elem += c;
         }
      }

      if(!elem.empty()) {
         oid_elems.push_back(to_u32bit(elem));
      }

      return oid_elems;
   } catch(Invalid_Argument&) {
      // thrown by to_u32bit
      return std::vector<uint32_t>();
   }
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

OID::OID(std::initializer_list<uint32_t> init) : m_id(init) {
   oid_valid_check(m_id);
}

OID::OID(std::vector<uint32_t>&& init) : m_id(std::move(init)) {
   oid_valid_check(m_id);
}

/*
* ASN.1 OID Constructor
*/
OID::OID(std::string_view oid_str) {
   if(!oid_str.empty()) {
      m_id = parse_oid_str(oid_str);
      oid_valid_check(m_id);
   }
}

/*
* Return this OID as a string
*/
std::string OID::to_string() const {
   std::ostringstream out;

   for(size_t i = 0; i != m_id.size(); ++i) {
      // avoid locale issues with integer formatting
      out << std::to_string(m_id[i]);
      if(i != m_id.size() - 1) {
         out << ".";
      }
   }

   return out.str();
}

std::string OID::to_formatted_string() const {
   std::string s = this->human_name_or_empty();
   if(!s.empty()) {
      return s;
   }
   return this->to_string();
}

std::string OID::human_name_or_empty() const {
   return OID_Map::global_registry().oid2str(*this);
}

bool OID::registered_oid() const {
   return !human_name_or_empty().empty();
}

/*
* Compare two OIDs
*/
bool operator<(const OID& a, const OID& b) {
   const std::vector<uint32_t>& oid1 = a.get_components();
   const std::vector<uint32_t>& oid2 = b.get_components();

   return std::lexicographical_compare(oid1.begin(), oid1.end(), oid2.begin(), oid2.end());
}

/*
* DER encode an OBJECT IDENTIFIER
*/
void OID::encode_into(DER_Encoder& der) const {
   if(m_id.size() < 2) {
      throw Invalid_Argument("OID::encode_into: OID is invalid");
   }

   auto append = [](std::vector<uint8_t>& encoding, uint32_t z) {
      if(z <= 0x7F) {
         encoding.push_back(static_cast<uint8_t>(z));
      } else {
         size_t z7 = (high_bit(z) + 7 - 1) / 7;

         for(size_t j = 0; j != z7; ++j) {
            uint8_t zp = static_cast<uint8_t>(z >> (7 * (z7 - j - 1)) & 0x7F);

            if(j != z7 - 1) {
               zp |= 0x80;
            }

            encoding.push_back(zp);
         }
      }
   };

   std::vector<uint8_t> encoding;

   // We know 40 * root can't overflow because root is between 0 and 2
   auto first = BOTAN_ASSERT_IS_SOME(checked_add(40 * m_id[0], m_id[1]));

   append(encoding, first);

   for(size_t i = 2; i != m_id.size(); ++i) {
      append(encoding, m_id[i]);
   }
   der.add_object(ASN1_Type::ObjectId, ASN1_Class::Universal, encoding);
}

/*
* Decode a BER encoded OBJECT IDENTIFIER
*/
void OID::decode_from(BER_Decoder& decoder) {
   BER_Object obj = decoder.get_next_object();
   if(obj.tagging() != (ASN1_Class::Universal | ASN1_Type::ObjectId)) {
      throw BER_Bad_Tag("Error decoding OID, unknown tag", obj.tagging());
   }

   if(obj.length() == 0) {
      throw BER_Decoding_Error("OID encoding is too short");
   }

   auto consume = [](BufferSlicer& data) -> uint32_t {
      BOTAN_ASSERT_NOMSG(!data.empty());
      uint32_t b = data.take_byte();

      if(b > 0x7F) {
         b &= 0x7F;

         // Even BER requires that the OID have minimal length, ie that
         // the first byte of a multibyte encoding cannot be zero
         // See X.690 section 8.19.2
         if(b == 0) {
            throw Decoding_Error("Leading zero byte in multibyte OID encoding");
         }

         while(true) {
            if(data.empty()) {
               throw Decoding_Error("Truncated OID value");
            }

            const uint8_t next = data.take_byte();
            const bool more = (next & 0x80);
            const uint8_t value = next & 0x7F;

            if((b >> (32 - 7)) != 0) {
               throw Decoding_Error("OID component overflow");
            }

            b = (b << 7) | value;

            if(!more) {
               break;
            }
         }
      }

      return b;
   };

   BufferSlicer data(obj.data());
   std::vector<uint32_t> parts;
   while(!data.empty()) {
      const uint32_t comp = consume(data);

      if(parts.empty()) {
         // divide into root and second arc

         const uint32_t root_arc = [](uint32_t b0) -> uint32_t {
            if(b0 < 40) {
               return 0;
            } else if(b0 < 80) {
               return 1;
            } else {
               return 2;
            }
         }(comp);

         parts.push_back(root_arc);
         BOTAN_ASSERT_NOMSG(comp >= 40 * root_arc);
         parts.push_back(comp - 40 * root_arc);
      } else {
         parts.push_back(comp);
      }
   }

   m_id = parts;
}

}  // namespace Botan
