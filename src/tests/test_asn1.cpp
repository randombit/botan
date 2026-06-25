/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ASN1)
   #include <botan/asn1_obj.h>
   #include <botan/asn1_print.h>
   #include <botan/asn1_time.h>
   #include <botan/ber_dec.h>
   #include <botan/bigint.h>
   #include <botan/data_src.h>
   #include <botan/der_enc.h>
   #include <botan/pss_params.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/parsing.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ASN1)

class ASN1_Test_Sequence final : public Botan::ASN1_Object {
   public:
      explicit ASN1_Test_Sequence(size_t value = 0) : m_value(value) {}

      void encode_into(Botan::DER_Encoder& der) const override { der.start_sequence().encode(m_value).end_cons(); }

      void decode_from(Botan::BER_Decoder& ber) override { ber.start_sequence().decode(m_value).end_cons(); }

      size_t value() const { return m_value; }

   private:
      size_t m_value;
};

Test::Result test_ber_stack_recursion() {
   Test::Result result("BER stack recursion");

   // OSS-Fuzz #813 GitHub #989

   try {
      const std::vector<uint8_t> in(10000000, 0);
      Botan::DataSource_Memory input(in.data(), in.size());
      Botan::BER_Decoder dec(input);

      while(dec.more_items()) {
         Botan::BER_Object obj;
         dec.get_next(obj);
      }
   } catch(Botan::Decoding_Error&) {}

   result.test_success("No crash");

   return result;
}

Test::Result test_ber_eoc_decoding_limits() {
   Test::Result result("BER nested indefinite length");

   // OSS-Fuzz #4353

   const Botan::ASN1_Pretty_Printer printer;

   size_t max_eoc_allowed = 0;

   for(size_t len = 1; len < 1024; ++len) {
      std::vector<uint8_t> buf(4 * len);

      /*
      This constructs a len deep sequence of SEQUENCES each with
      an indefinite length
      */
      for(size_t i = 0; i != 2 * len; i += 2) {
         buf[i] = 0x30;
         buf[i + 1] = 0x80;
      }
      // remainder of values left as zeros (EOC markers)

      try {
         printer.print(buf);
      } catch(Botan::BER_Decoding_Error&) {
         max_eoc_allowed = len - 1;
         break;
      }
   }

   result.test_sz_eq("EOC limited to prevent stack exhaustion", max_eoc_allowed, 16);

   return result;
}

Test::Result test_asn1_utf8_ascii_parsing() {
   Test::Result result("ASN.1 ASCII parsing");

   try {
      // \x13 - ASN1 tag for 'printable string'
      // \x06 - 6 characters of payload
      // ...  - UTF-8 encoded (ASCII chars only) word 'Moscow'
      const std::string moscow = "\x13\x06\x4D\x6F\x73\x63\x6F\x77";
      const std::string moscow_plain = "Moscow";
      Botan::DataSource_Memory input(moscow);
      Botan::BER_Decoder dec(input);

      Botan::ASN1_String str;
      str.decode_from(dec);

      result.test_str_eq("value()", str.value(), moscow_plain);
   } catch(const Botan::Decoding_Error& ex) {
      result.test_failure(ex.what());
   }

   return result;
}

Test::Result test_asn1_utf8_parsing() {
   Test::Result result("ASN.1 UTF-8 parsing");

   try {
      // \x0C - ASN1 tag for 'UTF8 string'
      // \x0C - 12 characters of payload
      // ...  - UTF-8 encoded russian word for Moscow in cyrillic script
      const std::string moscow = "\x0C\x0C\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      const std::string moscow_plain = "\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      Botan::DataSource_Memory input(moscow);
      Botan::BER_Decoder dec(input);

      Botan::ASN1_String str;
      str.decode_from(dec);

      result.test_str_eq("value()", str.value(), moscow_plain);
   } catch(const Botan::Decoding_Error& ex) {
      result.test_failure(ex.what());
   }

   return result;
}

Test::Result test_asn1_ucs2_parsing() {
   Test::Result result("ASN.1 BMP string (UCS-2) parsing");

   try {
      // \x1E     - ASN1 tag for 'BMP (UCS-2) string'
      // \x0C     - 12 characters of payload
      // ...      - UCS-2 encoding for Moscow in cyrillic script
      const std::string moscow = "\x1E\x0C\x04\x1C\x04\x3E\x04\x41\x04\x3A\x04\x32\x04\x30";
      const std::string moscow_plain = "\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";

      Botan::DataSource_Memory input(moscow);
      Botan::BER_Decoder dec(input);

      Botan::ASN1_String str;
      str.decode_from(dec);

      result.test_str_eq("value()", str.value(), moscow_plain);
   } catch(const Botan::Decoding_Error& ex) {
      result.test_failure(ex.what());
   }

   return result;
}

Test::Result test_asn1_ucs4_parsing() {
   Test::Result result("ASN.1 universal string (UCS-4) parsing");

   try {
      // \x1C - ASN1 tag for 'universal string'
      // \x18 - 24 characters of payload
      // ...  - UCS-4 encoding for Moscow in cyrillic script
      const uint8_t moscow[] =
         "\x1C\x18\x00\x00\x04\x1C\x00\x00\x04\x3E\x00\x00\x04\x41\x00\x00\x04\x3A\x00\x00\x04\x32\x00\x00\x04\x30";
      const std::string moscow_plain = "\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      Botan::DataSource_Memory input(moscow, sizeof(moscow));
      Botan::BER_Decoder dec(input);

      Botan::ASN1_String str;
      str.decode_from(dec);

      result.test_str_eq("value()", str.value(), moscow_plain);
   } catch(const Botan::Decoding_Error& ex) {
      result.test_failure(ex.what());
   }

   return result;
}

Test::Result test_asn1_ucs_invalid_codepoint_rejection() {
   Test::Result result("ASN.1 UCS-2/UCS-4 invalid codepoint rejection");

   auto expect_decode_throws = [&](const char* what, const std::vector<uint8_t>& wire) {
      result.test_throws(what, [&]() {
         Botan::DataSource_Memory input(wire.data(), wire.size());
         Botan::BER_Decoder dec(input);
         Botan::ASN1_String str;
         str.decode_from(dec);
      });
   };

   auto expect_decode_ok = [&](const char* what, const std::vector<uint8_t>& wire) {
      try {
         Botan::DataSource_Memory input(wire.data(), wire.size());
         Botan::BER_Decoder dec(input);
         Botan::ASN1_String str;
         str.decode_from(dec);
         result.test_success(what);
      } catch(const std::exception& ex) {
         result.test_failure(Botan::fmt("{}: unexpected throw: {}", what, ex.what()));
      }
   };

   // UniversalString (tag 0x1C) with codepoint 0x00110000 - one past Unicode max
   expect_decode_throws("UniversalString rejects codepoint > 0x10FFFF", {0x1C, 0x04, 0x00, 0x11, 0x00, 0x00});

   // UniversalString with codepoint 0xFFFFFFFF (clearly out of range)
   expect_decode_throws("UniversalString rejects codepoint 0xFFFFFFFF", {0x1C, 0x04, 0xFF, 0xFF, 0xFF, 0xFF});

   // UniversalString with high surrogate 0xD800
   expect_decode_throws("UniversalString rejects surrogate codepoint", {0x1C, 0x04, 0x00, 0x00, 0xD8, 0x00});

   // UniversalString boundary case: 0x10FFFF is the highest valid codepoint
   expect_decode_ok("UniversalString accepts codepoint 0x10FFFF", {0x1C, 0x04, 0x00, 0x10, 0xFF, 0xFF});

   // BmpString (tag 0x1E) with high surrogate
   expect_decode_throws("BmpString rejects surrogate codepoint", {0x1E, 0x02, 0xD8, 0x00});

   // BmpString with odd length is malformed
   expect_decode_throws("BmpString rejects odd-length payload", {0x1E, 0x03, 0x00, 0x41, 0x00});

   // UniversalString with non-multiple-of-4 length is malformed
   expect_decode_throws("UniversalString rejects non-multiple-of-4 payload",
                        {0x1C, 0x05, 0x00, 0x00, 0x00, 0x41, 0x00});

   return result;
}

Test::Result test_asn1_ascii_encoding() {
   Test::Result result("ASN.1 ASCII encoding");

   try {
      // UTF-8 encoded (ASCII chars only) word 'Moscow'
      const std::string moscow = "Moscow";
      const Botan::ASN1_String str(moscow);

      Botan::DER_Encoder enc;

      str.encode_into(enc);
      auto encodingResult = enc.get_contents();

      // \x13 - ASN1 tag for 'printable string'
      // \x06 - 6 characters of payload
      result.test_bin_eq("encoding result", encodingResult, "13064D6F73636F77");

      result.test_success("No crash");
   } catch(const std::exception& ex) {
      result.test_failure(ex.what());
   }

   return result;
}

Test::Result test_asn1_utf8_encoding() {
   Test::Result result("ASN.1 UTF-8 encoding");

   try {
      // UTF-8 encoded russian word for Moscow in cyrillic script
      const std::string moscow = "\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      const Botan::ASN1_String str(moscow);

      Botan::DER_Encoder enc;

      str.encode_into(enc);
      auto encodingResult = enc.get_contents();

      // \x0C - ASN1 tag for 'UTF8 string'
      // \x0C - 12 characters of payload
      result.test_bin_eq("encoding result", encodingResult, "0C0CD09CD0BED181D0BAD0B2D0B0");

      result.test_success("No crash");
   } catch(const std::exception& ex) {
      result.test_failure(ex.what());
   }

   return result;
}

Test::Result test_asn1_tag_underlying_type() {
   Test::Result result("ASN.1 class and type underlying type");

   if constexpr(std::is_same_v<std::underlying_type_t<Botan::ASN1_Class>, std::underlying_type_t<Botan::ASN1_Type>>) {
      if constexpr(!std::is_same_v<std::underlying_type_t<Botan::ASN1_Class>,
                                   std::invoke_result_t<decltype(&Botan::BER_Object::tagging), Botan::BER_Object>>) {
         result.test_failure(
            "Return type of BER_Object::tagging() is different than the underlying type of ASN1_Class");
      } else {
         result.test_success("Same types");
      }
   } else {
      result.test_failure("ASN1_Class and ASN1_Type have different underlying types");
   }

   return result;
}

Test::Result test_asn1_negative_int_encoding() {
   Test::Result result("DER encode/decode of negative integers");

   BigInt n(32);

   for(size_t i = 0; i != 2048; ++i) {
      n--;

      const auto enc = Botan::DER_Encoder().encode(n).get_contents_unlocked();

      BigInt n_dec;
      Botan::BER_Decoder(enc, Botan::BER_Decoder::Limits::DER()).decode(n_dec);

      result.test_bn_eq("DER encoding round trips negative integers", n_dec, n);
   }

   return result;
}

Test::Result test_der_constructed_tag_17_not_sorted() {
   Test::Result result("DER constructed [17] is not SET-sorted");

   // Two INTEGERs in descending order. A universal SET would lex-sort and put
   // 0x01 before 0x02; a non-universal constructed [17] must preserve order.
   const std::vector<uint8_t> first = {0x02, 0x01, 0x02};   // INTEGER 2
   const std::vector<uint8_t> second = {0x02, 0x01, 0x01};  // INTEGER 1

   auto encode_with = [&](auto starter) {
      Botan::DER_Encoder enc;
      starter(enc).raw_bytes(first).raw_bytes(second).end_cons();
      return enc.get_contents_unlocked();
   };

   // Reference: a universal SET of the same children gets sorted
   const auto set_enc = encode_with([](Botan::DER_Encoder& e) -> Botan::DER_Encoder& { return e.start_set(); });
   const std::vector<uint8_t> set_expected = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
   result.test_bin_eq("universal SET is lex-sorted", set_enc, set_expected);

   // start_context_specific(17): tag byte = ContextSpecific | Constructed | 17 = 0xB1
   const auto ctx_enc =
      encode_with([](Botan::DER_Encoder& e) -> Botan::DER_Encoder& { return e.start_context_specific(17); });
   const std::vector<uint8_t> ctx_expected = {0xB1, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01};
   result.test_bin_eq("context-specific [17] preserves order", ctx_enc, ctx_expected);

   // start_explicit_context_specific(17): same tag byte 0xB1
   const auto explicit_ctx_enc =
      encode_with([](Botan::DER_Encoder& e) -> Botan::DER_Encoder& { return e.start_explicit_context_specific(17); });
   result.test_bin_eq("explicit context-specific [17] preserves order", explicit_ctx_enc, ctx_expected);

   // start_explicit(17): used to throw Internal_Error; must now produce [17] in order
   const auto explicit_enc =
      encode_with([](Botan::DER_Encoder& e) -> Botan::DER_Encoder& { return e.start_explicit(17); });
   result.test_bin_eq("start_explicit(17) preserves order", explicit_enc, ctx_expected);

   return result;
}

Test::Result test_der_implicit_tagging_helpers() {
   Test::Result result("DER implicit tagging helpers");

   const std::vector<uint8_t> first = {0x02, 0x01, 0x02};   // INTEGER 2
   const std::vector<uint8_t> second = {0x02, 0x01, 0x01};  // INTEGER 1

   Botan::DER_Encoder set_enc;
   set_enc.start_set(23).raw_bytes(first).raw_bytes(second).end_cons();
   const auto implicit_set = set_enc.get_contents_unlocked();
   result.test_bin_eq("implicit SET is still sorted", implicit_set, "B706020101020102");

   const ASN1_Test_Sequence seq(42);
   const auto implicit_seq = Botan::DER_Encoder().encode_implicit(seq, Botan::ASN1_Type(3)).get_contents_unlocked();
   result.test_bin_eq("implicit constructed object keeps constructed bit", implicit_seq, "A30302012A");

   ASN1_Test_Sequence decoded;
   Botan::BER_Decoder(implicit_seq, Botan::BER_Decoder::Limits::DER())
      .decode_implicit(decoded,
                       Botan::ASN1_Type(3),
                       Botan::ASN1_Class::ContextSpecific | Botan::ASN1_Class::Constructed,
                       Botan::ASN1_Type::Sequence,
                       Botan::ASN1_Class::Constructed)
      .verify_end();
   result.test_sz_eq("implicit constructed object decodes", decoded.value(), 42);

   const std::vector<uint8_t> one_bit = {0x80};
   const auto implicit_bitstring =
      Botan::DER_Encoder()
         .encode_bitstring(one_bit, 7, Botan::ASN1_Type(1), Botan::ASN1_Class::ContextSpecific)
         .get_contents_unlocked();
   result.test_bin_eq("implicit BIT STRING keeps unused bit count", implicit_bitstring, "81020780");

   const std::vector<uint8_t> bad_padding = {0x81};
   result.test_throws<Botan::Invalid_Argument>("BIT STRING unused bits must be zero",
                                               [&] { Botan::DER_Encoder().encode_bitstring(bad_padding, 7); });

   return result;
}

Test::Result test_asn1_bitstring_helpers() {
   Test::Result result("ASN.1 BIT STRING helpers");

   const std::vector<uint8_t> raw_der = {0x03, 0x03, 0x03, 0xA8, 0x00};
   Botan::ASN1_BitString raw_bits;
   Botan::BER_Decoder(raw_der, Botan::BER_Decoder::Limits::DER()).decode_bitstring(raw_bits).verify_end();

   result.test_sz_eq("raw bytes", raw_bits.bytes().size(), 2);
   result.test_sz_eq("raw unused bits", raw_bits.unused_bits(), 3);
   result.test_sz_eq("raw bit length", raw_bits.bit_length(), 13);
   result.test_is_true("raw bit 0", raw_bits.bit_at(0));
   result.test_is_false("raw bit 1", raw_bits.bit_at(1));
   result.test_is_true("raw bit 2", raw_bits.bit_at(2));

   const auto raw_reencoded = Botan::DER_Encoder().encode_bitstring(raw_bits).get_contents_unlocked();
   result.test_bin_eq("raw BIT STRING re-encodes", raw_reencoded, raw_der);

   const std::vector<uint8_t> octet_aligned_der = {0x03, 0x02, 0x00, 0xAA};
   std::vector<uint8_t> octets;
   Botan::BER_Decoder(octet_aligned_der, Botan::BER_Decoder::Limits::DER())
      .decode_octet_aligned_bitstring(octets)
      .verify_end();
   const std::vector<uint8_t> expected_octets = {0xAA};
   result.test_bin_eq("octet-aligned BIT STRING decodes as bytes", octets, expected_octets);

   const std::vector<uint8_t> non_octet_aligned_der = {0x03, 0x02, 0x01, 0x80};
   result.test_throws<Botan::Decoding_Error>("octet-aligned BIT STRING rejects unused bits", [&] {
      std::vector<uint8_t> rejected;
      Botan::BER_Decoder(non_octet_aligned_der, Botan::BER_Decoder::Limits::DER())
         .decode_octet_aligned_bitstring(rejected)
         .verify_end();
   });

   const uint64_t named = (uint64_t(1) << 15) | (uint64_t(1) << 7);
   const auto named_der = Botan::DER_Encoder().encode_named_bitstring(named, 16).get_contents_unlocked();
   const std::vector<uint8_t> expected_named_der = {0x03, 0x03, 0x07, 0x80, 0x80};
   result.test_bin_eq("named BIT STRING uses DER minimum length", named_der, expected_named_der);

   uint64_t decoded_named = 0;
   Botan::BER_Decoder(named_der, Botan::BER_Decoder::Limits::DER())
      .decode_named_bitstring(decoded_named, 16)
      .verify_end();
   result.test_u64_eq("named BIT STRING round-trips", decoded_named, named);

   const auto width9_der = Botan::DER_Encoder().encode_named_bitstring(1, 9).get_contents_unlocked();
   const std::vector<uint8_t> expected_width9_der = {0x03, 0x03, 0x07, 0x00, 0x80};
   result.test_bin_eq("named BIT STRING handles non-byte width", width9_der, expected_width9_der);

   const std::vector<uint8_t> non_minimal_named_der = {0x03, 0x02, 0x00, 0x80};
   result.test_throws<Botan::BER_Decoding_Error>("DER named BIT STRING rejects trailing zero bits", [&] {
      uint64_t rejected = 0;
      Botan::BER_Decoder(non_minimal_named_der, Botan::BER_Decoder::Limits::DER())
         .decode_named_bitstring(rejected, 16)
         .verify_end();
   });

   uint64_t non_minimal_named = 0;
   Botan::BER_Decoder(non_minimal_named_der, Botan::BER_Decoder::Limits::BER())
      .decode_named_bitstring(non_minimal_named, 16)
      .verify_end();
   result.test_u64_eq("BER named BIT STRING accepts trailing zero bits", non_minimal_named, uint64_t(1) << 15);

   return result;
}

Test::Result test_ber_indefinite_length_trailing_data() {
   Test::Result result("BER indefinite length trailing data");

   // Case 1: verify_end after consuming indef SEQUENCE
   try {
      const std::vector<uint8_t> enc = {0x30, 0x80, 0x02, 0x01, 0x42, 0x00, 0x00};
      Botan::BER_Decoder dec(enc);
      Botan::BigInt x;
      dec.start_sequence().decode(x).end_cons();
      dec.verify_end();
      result.test_bn_eq("verify_end decoded x", x, Botan::BigInt(0x42));
   } catch(Botan::Exception& e) {
      result.test_failure("verify_end after indef SEQUENCE", e.what());
   }

   // Case 2: two back-to-back indef SEQUENCES at top level
   try {
      const std::vector<uint8_t> enc = {
         0x30, 0x80, 0x02, 0x01, 0x42, 0x00, 0x00, 0x30, 0x80, 0x02, 0x01, 0x43, 0x00, 0x00};
      Botan::BER_Decoder dec(enc);
      Botan::BigInt x;
      Botan::BigInt y;
      dec.start_sequence().decode(x).end_cons();
      dec.start_sequence().decode(y).end_cons();
      dec.verify_end();
      result.test_bn_eq("back-to-back x", x, Botan::BigInt(0x42));
      result.test_bn_eq("back-to-back y", y, Botan::BigInt(0x43));
   } catch(Botan::Exception& e) {
      result.test_failure("two back-to-back indef SEQUENCES", e.what());
   }

   // Case 3: nested indef SEQUENCES
   try {
      const std::vector<uint8_t> enc = {0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x42, 0x00, 0x00, 0x00, 0x00};
      Botan::BER_Decoder dec(enc);
      Botan::BigInt x;
      auto outer = dec.start_sequence();
      outer.start_sequence().decode(x).end_cons();
      outer.end_cons();
      dec.verify_end();
      result.test_bn_eq("nested x", x, Botan::BigInt(0x42));
   } catch(Botan::Exception& e) {
      result.test_failure("nested indef SEQUENCE", e.what());
   }

   // Case 4: while(more_items()) loop over an indef SEQUENCE
   try {
      const std::vector<uint8_t> enc = {0x30, 0x80, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43, 0x00, 0x00};
      Botan::BER_Decoder dec(enc);
      auto seq = dec.start_sequence();
      std::vector<Botan::BigInt> xs;
      while(seq.more_items()) {
         Botan::BigInt x;
         seq.decode(x);
         xs.push_back(x);
      }
      seq.end_cons();
      dec.verify_end();
      result.test_sz_eq("more_items count", xs.size(), 2);
      if(xs.size() == 2) {
         result.test_bn_eq("more_items xs[0]", xs[0], Botan::BigInt(0x42));
         result.test_bn_eq("more_items xs[1]", xs[1], Botan::BigInt(0x43));
      }
   } catch(Botan::Exception& e) {
      result.test_failure("more_items loop over indef SEQUENCE", e.what());
   }

   return result;
}

Test::Result test_ber_find_eoc() {
   Test::Result result("BER indefinite length EOC matching");

   const size_t num_siblings = 4096;

   std::vector<uint8_t> ber;
   ber.push_back(0x30);  // outer SEQUENCE | CONSTRUCTED
   ber.push_back(0x80);  // indefinite length
   for(size_t i = 0; i != num_siblings; ++i) {
      ber.push_back(0x30);  // inner SEQUENCE | CONSTRUCTED
      ber.push_back(0x80);  // indefinite length
      ber.push_back(0x00);  // EOC tag
      ber.push_back(0x00);  // EOC length
   }
   ber.push_back(0x00);  // outer EOC tag
   ber.push_back(0x00);  // outer EOC length

   try {
      Botan::BER_Decoder dec(ber);
      const Botan::BER_Object obj = dec.get_next_object();

      result.test_sz_eq("object body includes children", obj.length(), num_siblings * 4);
   } catch(Botan::Exception& e) {
      result.test_failure("decode failed", e.what());
   }

   return result;
}

Test::Result test_asn1_string_zero_length_roundtrip() {
   Test::Result result("ASN.1 String zero-length round-trip");

   auto roundtrip = [&](const char* what, const std::vector<uint8_t>& wire) {
      try {
         Botan::DataSource_Memory input(wire.data(), wire.size());
         Botan::BER_Decoder dec(input);
         Botan::ASN1_String str;
         str.decode_from(dec);

         Botan::DER_Encoder enc;
         str.encode_into(enc);
         const auto out = enc.get_contents();
         result.test_bin_eq(what, std::span{out}, std::span{wire});
      } catch(const std::exception& ex) {
         result.test_failure(Botan::fmt("{}: unexpected throw: {}", what, ex.what()));
      }
   };

   roundtrip("BmpString 1E 00", {0x1E, 0x00});
   roundtrip("UniversalString 1C 00", {0x1C, 0x00});
   roundtrip("TeletexString 14 00", {0x14, 0x00});

   return result;
}

Test::Result test_pss_params_rejects_trailing_data_in_mgf1_params() {
   Test::Result result("PSS-Params rejects trailing data in MGF1 parameters");

   const Botan::AlgorithmIdentifier sha256_alg_id("SHA-256", Botan::AlgorithmIdentifier::USE_NULL_PARAM);
   const auto sha256_der = sha256_alg_id.BER_encode();

   auto encode_pss_params = [](const Botan::AlgorithmIdentifier& hash, const Botan::AlgorithmIdentifier& mgf_hash) {
      const Botan::AlgorithmIdentifier mgf("MGF1", mgf_hash.BER_encode());
      Botan::DER_Encoder enc;
      enc.start_sequence()
         .start_context_specific(0)
         .encode(hash)
         .end_cons()
         .start_context_specific(1)
         .encode(mgf)
         .end_cons()
         .start_context_specific(2)
         .encode(static_cast<size_t>(32))
         .end_cons()
         .end_cons();
      return enc.get_contents();
   };

   try {
      const auto clean_der = encode_pss_params(sha256_alg_id, sha256_alg_id);
      const Botan::PSS_Params clean(clean_der);
      result.test_success("control: clean PSS-Params decodes");
   } catch(const std::exception& e) {
      result.test_failure(Botan::fmt("clean PSS-Params unexpected throw: {}", e.what()));
   }

   std::vector<uint8_t> mgf_params_with_junk = sha256_der;
   const std::vector<uint8_t> trailing_junk{0x02, 0x01, 0x00};
   mgf_params_with_junk.insert(mgf_params_with_junk.end(), trailing_junk.begin(), trailing_junk.end());
   const Botan::AlgorithmIdentifier mgf_with_trailing_junk("MGF1", mgf_params_with_junk);

   Botan::DER_Encoder bad_mgf_params_enc;
   bad_mgf_params_enc.start_sequence()
      .start_context_specific(0)
      .encode(sha256_alg_id)
      .end_cons()
      .start_context_specific(1)
      .encode(mgf_with_trailing_junk)
      .end_cons()
      .start_context_specific(2)
      .encode(static_cast<size_t>(32))
      .end_cons()
      .end_cons();
   const auto bad_der = bad_mgf_params_enc.get_contents();

   result.test_throws<Botan::Decoding_Error>("PSS-Params rejects trailing data in MGF1 parameters",
                                             [&]() { const Botan::PSS_Params bad(bad_der); });

   const Botan::AlgorithmIdentifier sha256_with_params("SHA-256", std::vector<uint8_t>{0x04, 0x00});

   result.test_throws<Botan::Decoding_Error>("PSS-Params rejects hash AlgorithmIdentifier parameters", [&]() {
      const auto bad_hash_der = encode_pss_params(sha256_with_params, sha256_alg_id);
      const Botan::PSS_Params bad(bad_hash_der);
   });

   result.test_throws<Botan::Decoding_Error>("PSS-Params rejects MGF1 hash AlgorithmIdentifier parameters", [&]() {
      const auto bad_mgf_hash_der = encode_pss_params(sha256_alg_id, sha256_with_params);
      const Botan::PSS_Params bad(bad_mgf_hash_der);
   });

   return result;
}

class ASN1_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_ber_stack_recursion());
         results.push_back(test_ber_eoc_decoding_limits());
         results.push_back(test_ber_indefinite_length_trailing_data());
         results.push_back(test_ber_find_eoc());
         results.push_back(test_asn1_utf8_ascii_parsing());
         results.push_back(test_asn1_utf8_parsing());
         results.push_back(test_asn1_ucs2_parsing());
         results.push_back(test_asn1_ucs4_parsing());
         results.push_back(test_asn1_ucs_invalid_codepoint_rejection());
         results.push_back(test_asn1_ascii_encoding());
         results.push_back(test_asn1_utf8_encoding());
         results.push_back(test_asn1_tag_underlying_type());
         results.push_back(test_asn1_negative_int_encoding());
         results.push_back(test_der_constructed_tag_17_not_sorted());
         results.push_back(test_der_implicit_tagging_helpers());
         results.push_back(test_asn1_bitstring_helpers());
         results.push_back(test_asn1_string_zero_length_roundtrip());
         results.push_back(test_pss_params_rejects_trailing_data_in_mgf1_params());

         return results;
      }
};

BOTAN_REGISTER_TEST("asn1", "asn1_encoding", ASN1_Tests);

class ASN1_Time_Parsing_Tests final : public Text_Based_Test {
   public:
      ASN1_Time_Parsing_Tests() : Text_Based_Test("asn1_time.vec", "Tspec") {}

      Test::Result run_one_test(const std::string& tag_str, const VarMap& vars) override {
         Test::Result result("ASN.1 date parsing");

         const std::string tspec = vars.get_req_str("Tspec");

         if(tag_str != "UTC" && tag_str != "UTC.invalid" && tag_str != "Generalized" &&
            tag_str != "Generalized.invalid") {
            throw Test_Error("Invalid tag value in ASN1 date parsing test");
         }

         const bool out_of_range = [&]() -> bool {
            if(tspec.size() == 15) {
               const size_t year = Botan::to_u32bit(std::string_view(tspec).substr(0, 4));
               if(year >= 2262) {
                  return true;
               }
               if(year >= 2038 && sizeof(time_t) == 4) {
                  return true;
               }
            }

            return false;
         }();

         const Botan::ASN1_Type tag = (tag_str == "UTC" || tag_str == "UTC.invalid")
                                         ? Botan::ASN1_Type::UtcTime
                                         : Botan::ASN1_Type::GeneralizedTime;

         const bool valid = tag_str.find(".invalid") == std::string::npos;

         if(valid) {
            const Botan::ASN1_Time time(tspec, tag);
            result.test_success("Accepted valid time");

            try {
               const auto std_timepoint = time.to_std_timepoint();
               result.test_success("Was able to convert time to std timepoint");

               const auto from_std_timepoint = Botan::ASN1_Time::from_time_point(std_timepoint);
               result.test_is_true("ASN1_Time from std timepoint matches input", from_std_timepoint == time);
            } catch(std::exception& e) {
               if(out_of_range) {
                  result.test_str_contains("Exception message", e.what(), "time is outside the representable range");
               } else {
                  result.test_failure("Was not able to convert time to std timepoint", e.what());
               }
            }
         } else {
            result.test_throws("Invalid time rejected", [=]() { const Botan::ASN1_Time time(tspec, tag); });
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("asn1", "asn1_time", ASN1_Time_Parsing_Tests);

class ASN1_String_Validation_Tests final : public Text_Based_Test {
   public:
      ASN1_String_Validation_Tests() :
            Text_Based_Test("asn1_string_validation.vec",
                            "Input,ValidNumeric,ValidPrintable,ValidIa5,ValidVisible,ValidUtf8") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("ASN.1 string validation");

         const auto input = vars.get_req_str("Input");
         const bool valid_numeric = vars.get_req_bool("ValidNumeric");
         const bool valid_printable = vars.get_req_bool("ValidPrintable");
         const bool valid_ia5 = vars.get_req_bool("ValidIa5");
         const bool valid_visible = vars.get_req_bool("ValidVisible");
         const bool valid_utf8 = vars.get_req_bool("ValidUtf8");

         test_string_type(result, input, "NumericString", Botan::ASN1_Type::NumericString, valid_numeric);
         test_string_type(result, input, "PrintableString", Botan::ASN1_Type::PrintableString, valid_printable);
         test_string_type(result, input, "Ia5String", Botan::ASN1_Type::Ia5String, valid_ia5);
         test_string_type(result, input, "VisibleString", Botan::ASN1_Type::VisibleString, valid_visible);
         test_string_type(result, input, "Utf8String", Botan::ASN1_Type::Utf8String, valid_utf8);

         if(valid_utf8) {
            try {
               const Botan::ASN1_String str(input);
               const auto expected_tag =
                  valid_printable ? Botan::ASN1_Type::PrintableString : Botan::ASN1_Type::Utf8String;
               result.test_u32_eq("String tagging categorization",
                                  static_cast<uint32_t>(str.tagging()),
                                  static_cast<uint32_t>(expected_tag));
            } catch(const std::exception& ex) {
               result.test_failure(Botan::fmt("default constructor unexpectedly rejected '{}': {}", input, ex.what()));
            }
         }

         return result;
      }

   private:
      void test_string_type(Test::Result& result,
                            std::string_view input,
                            std::string_view type,
                            Botan::ASN1_Type tag,
                            bool expected_valid) {
         if(expected_valid) {
            try {
               const Botan::ASN1_String str(input, tag);
               result.test_str_eq(Botan::fmt("{} constructor value", type), str.value(), input);

               const auto enc = raw_encode_string(input, tag);
               Botan::BER_Decoder dec(enc);
               Botan::ASN1_String decoded;
               decoded.decode_from(dec);
               result.test_str_eq(Botan::fmt("{} decode value", type), decoded.value(), input);
            } catch(const std::exception& e) {
               result.test_failure(Botan::fmt("{} unexpectedly rejected '{}': {}", type, input, e.what()));
            }
         } else {
            result.test_throws(Botan::fmt("{} constructor rejects", type),
                               [&]() { const Botan::ASN1_String str(input, tag); });

            result.test_throws(Botan::fmt("{} decode rejects", type), [&]() {
               const auto enc = raw_encode_string(input, tag);
               Botan::BER_Decoder dec(enc);
               Botan::ASN1_String decoded;
               decoded.decode_from(dec);
            });
         }
      }

      static std::vector<uint8_t> raw_encode_string(std::string_view input, Botan::ASN1_Type tag) {
         std::vector<uint8_t> encoding;
         Botan::DER_Encoder der(encoding);
         der.add_object(tag, Botan::ASN1_Class::Universal, input);
         return encoding;
      }
};

BOTAN_REGISTER_TEST("asn1", "asn1_string_validation", ASN1_String_Validation_Tests);

class ASN1_Printer_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("ASN1_Pretty_Printer");

         const Botan::ASN1_Pretty_Printer printer;

         const size_t num_tests = 8;

         for(size_t i = 1; i <= num_tests; ++i) {
            const std::string i_str = std::to_string(i);
            const std::vector<uint8_t> input_data = Test::read_binary_data_file("asn1_print/input" + i_str + ".der");
            const std::string expected_output = Test::read_data_file("asn1_print/output" + i_str + ".txt");

            try {
               const std::string output = printer.print(input_data);
               result.test_str_eq("Test " + i_str, output, expected_output);
            } catch(Botan::Exception& e) {
               result.test_failure(Botan::fmt("Printing test {} failed with an exception: '{}'", i, e.what()));
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("asn1", "asn1_printer", ASN1_Printer_Tests);

class ASN1_Decoding_Tests final : public Text_Based_Test {
   public:
      ASN1_Decoding_Tests() : Text_Based_Test("asn1_decoding.vec", "Input,ResultBER", "ResultDER") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const auto input = vars.get_req_bin("Input");
         const std::string expected_ber = vars.get_req_str("ResultBER");
         const std::string expected_der = vars.get_opt_str("ResultDER", expected_ber);

         Test::Result result("ASN1 decoding");

         decoding_test(result, input, expected_ber, false);
         decoding_test(result, input, expected_der, true);

         return result;
      }

   private:
      static void decoding_test(Test::Result& result,
                                std::span<const uint8_t> input,
                                std::string_view expected,
                                bool require_der) {
         const Botan::ASN1_Pretty_Printer printer(4096, 2048, true, 0, 60, 64, require_der);
         const std::string mode = require_der ? "DER" : "BER";
         std::ostringstream sink;

         try {
            printer.print_to_stream(sink, input.data(), input.size());

            if(expected == "OK") {
               result.test_success();
            } else {
               result.test_failure(Botan::fmt("Accepted invalid {} input, expected error {}", mode, expected));
            }
         } catch(const std::exception& e) {
            if(expected == "OK") {
               result.test_failure(Botan::fmt("Rejected valid {} input with {}", mode, e.what()));
            } else {
               // BER_Decoding_Error prepends "BER: " to the message
               std::string msg = e.what();
               if(msg.starts_with("BER: ")) {
                  msg = msg.substr(5);
               }
               result.test_str_eq("error message", msg, expected);
            }
         }
      }
};

BOTAN_REGISTER_TEST("asn1", "asn1_decoding", ASN1_Decoding_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
