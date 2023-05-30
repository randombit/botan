/*
* Character Set Handling
* (C) 1999-2007,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/charset.h>

#include <botan/exceptn.h>
#include <botan/internal/loadstor.h>
#include <sstream>

namespace Botan {

namespace {

void append_utf8_for(std::string& s, uint32_t c) {
   if(c >= 0xD800 && c < 0xE000) {
      throw Decoding_Error("Invalid Unicode character");
   }

   if(c <= 0x7F) {
      const uint8_t b0 = static_cast<uint8_t>(c);
      s.push_back(static_cast<char>(b0));
   } else if(c <= 0x7FF) {
      const uint8_t b0 = 0xC0 | static_cast<uint8_t>(c >> 6);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
   } else if(c <= 0xFFFF) {
      const uint8_t b0 = 0xE0 | static_cast<uint8_t>(c >> 12);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>((c >> 6) & 0x3F);
      const uint8_t b2 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      s.push_back(static_cast<char>(b2));
   } else if(c <= 0x10FFFF) {
      const uint8_t b0 = 0xF0 | static_cast<uint8_t>(c >> 18);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>((c >> 12) & 0x3F);
      const uint8_t b2 = 0x80 | static_cast<uint8_t>((c >> 6) & 0x3F);
      const uint8_t b3 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      s.push_back(static_cast<char>(b2));
      s.push_back(static_cast<char>(b3));
   } else {
      throw Decoding_Error("Invalid Unicode character");
   }
}

}  // namespace

std::string ucs2_to_utf8(const uint8_t ucs2[], size_t len) {
   if(len % 2 != 0) {
      throw Decoding_Error("Invalid length for UCS-2 string");
   }

   const size_t chars = len / 2;

   std::string s;
   for(size_t i = 0; i != chars; ++i) {
      const uint32_t c = load_be<uint16_t>(ucs2, i);
      append_utf8_for(s, c);
   }

   return s;
}

std::string ucs4_to_utf8(const uint8_t ucs4[], size_t len) {
   if(len % 4 != 0) {
      throw Decoding_Error("Invalid length for UCS-4 string");
   }

   const size_t chars = len / 4;

   std::string s;
   for(size_t i = 0; i != chars; ++i) {
      const uint32_t c = load_be<uint32_t>(ucs4, i);
      append_utf8_for(s, c);
   }

   return s;
}

/*
* Convert from ISO 8859-1 to UTF-8
*/
std::string latin1_to_utf8(const uint8_t chars[], size_t len) {
   std::string s;
   for(size_t i = 0; i != len; ++i) {
      const uint32_t c = static_cast<uint8_t>(chars[i]);
      append_utf8_for(s, c);
   }
   return s;
}

std::string format_char_for_display(char c) {
   std::ostringstream oss;

   oss << "'";

   if(c == '\t') {
      oss << "\\t";
   } else if(c == '\n') {
      oss << "\\n";
   } else if(c == '\r') {
      oss << "\\r";
   } else if(static_cast<unsigned char>(c) >= 128) {
      unsigned char z = static_cast<unsigned char>(c);
      oss << "\\x" << std::hex << std::uppercase << static_cast<int>(z);
   } else {
      oss << c;
   }

   oss << "'";

   return oss.str();
}

}  // namespace Botan
