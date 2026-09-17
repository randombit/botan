/*
 * XMSS^MT Parameters
 * Describes a signature method for XMSS^MT, as defined in:
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 * [2] Recommendation for Stateful Hash-Based Signature Schemes
 *     NIST Special Publication 800-208
 *     Release: October 2020.
 *     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf
 *
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmssmt_parameters.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

XMSSMT_Parameters::xmssmt_algorithm_t XMSSMT_Parameters::parse_oid(std::span<const uint8_t> bytes) {
   if(bytes.size() != 4) {
      throw Decoding_Error("can't parse invalid XMSS^MT OID length.");
   }

   uint32_t raw_id = 0;
   for(size_t i = 0; i < 4; i++) {
      raw_id = ((raw_id << 8) | bytes[i]);
   }
   return static_cast<XMSSMT_Parameters::xmssmt_algorithm_t>(raw_id);
}

XMSSMT_Parameters::xmssmt_algorithm_t XMSSMT_Parameters::xmssmt_id_from_string(std::string_view param_set) {
   if(param_set == "XMSSMT-SHA2_20/2_256") {
      return XMSSMT_SHA2_20_2_256;
   }
   if(param_set == "XMSSMT-SHA2_20/4_256") {
      return XMSSMT_SHA2_20_4_256;
   }
   if(param_set == "XMSSMT-SHA2_40/2_256") {
      return XMSSMT_SHA2_40_2_256;
   }
   if(param_set == "XMSSMT-SHA2_40/4_256") {
      return XMSSMT_SHA2_40_4_256;
   }
   if(param_set == "XMSSMT-SHA2_40/8_256") {
      return XMSSMT_SHA2_40_8_256;
   }
   if(param_set == "XMSSMT-SHA2_60/3_256") {
      return XMSSMT_SHA2_60_3_256;
   }
   if(param_set == "XMSSMT-SHA2_60/6_256") {
      return XMSSMT_SHA2_60_6_256;
   }
   if(param_set == "XMSSMT-SHA2_60/12_256") {
      return XMSSMT_SHA2_60_12_256;
   }
   if(param_set == "XMSSMT-SHA2_20/2_512") {
      return XMSSMT_SHA2_20_2_512;
   }
   if(param_set == "XMSSMT-SHA2_20/4_512") {
      return XMSSMT_SHA2_20_4_512;
   }
   if(param_set == "XMSSMT-SHA2_40/2_512") {
      return XMSSMT_SHA2_40_2_512;
   }
   if(param_set == "XMSSMT-SHA2_40/4_512") {
      return XMSSMT_SHA2_40_4_512;
   }
   if(param_set == "XMSSMT-SHA2_40/8_512") {
      return XMSSMT_SHA2_40_8_512;
   }
   if(param_set == "XMSSMT-SHA2_60/3_512") {
      return XMSSMT_SHA2_60_3_512;
   }
   if(param_set == "XMSSMT-SHA2_60/6_512") {
      return XMSSMT_SHA2_60_6_512;
   }
   if(param_set == "XMSSMT-SHA2_60/12_512") {
      return XMSSMT_SHA2_60_12_512;
   }
   if(param_set == "XMSSMT-SHAKE_20/2_256") {
      return XMSSMT_SHAKE_20_2_256;
   }
   if(param_set == "XMSSMT-SHAKE_20/4_256") {
      return XMSSMT_SHAKE_20_4_256;
   }
   if(param_set == "XMSSMT-SHAKE_40/2_256") {
      return XMSSMT_SHAKE_40_2_256;
   }
   if(param_set == "XMSSMT-SHAKE_40/4_256") {
      return XMSSMT_SHAKE_40_4_256;
   }
   if(param_set == "XMSSMT-SHAKE_40/8_256") {
      return XMSSMT_SHAKE_40_8_256;
   }
   if(param_set == "XMSSMT-SHAKE_60/3_256") {
      return XMSSMT_SHAKE_60_3_256;
   }
   if(param_set == "XMSSMT-SHAKE_60/6_256") {
      return XMSSMT_SHAKE_60_6_256;
   }
   if(param_set == "XMSSMT-SHAKE_60/12_256") {
      return XMSSMT_SHAKE_60_12_256;
   }
   if(param_set == "XMSSMT-SHAKE_20/2_512") {
      return XMSSMT_SHAKE_20_2_512;
   }
   if(param_set == "XMSSMT-SHAKE_20/4_512") {
      return XMSSMT_SHAKE_20_4_512;
   }
   if(param_set == "XMSSMT-SHAKE_40/2_512") {
      return XMSSMT_SHAKE_40_2_512;
   }
   if(param_set == "XMSSMT-SHAKE_40/4_512") {
      return XMSSMT_SHAKE_40_4_512;
   }
   if(param_set == "XMSSMT-SHAKE_40/8_512") {
      return XMSSMT_SHAKE_40_8_512;
   }
   if(param_set == "XMSSMT-SHAKE_60/3_512") {
      return XMSSMT_SHAKE_60_3_512;
   }
   if(param_set == "XMSSMT-SHAKE_60/6_512") {
      return XMSSMT_SHAKE_60_6_512;
   }
   if(param_set == "XMSSMT-SHAKE_60/12_512") {
      return XMSSMT_SHAKE_60_12_512;
   }
   if(param_set == "XMSSMT-SHA2_20/2_192") {
      return XMSSMT_SHA2_20_2_192;
   }
   if(param_set == "XMSSMT-SHA2_20/4_192") {
      return XMSSMT_SHA2_20_4_192;
   }
   if(param_set == "XMSSMT-SHA2_40/2_192") {
      return XMSSMT_SHA2_40_2_192;
   }
   if(param_set == "XMSSMT-SHA2_40/4_192") {
      return XMSSMT_SHA2_40_4_192;
   }
   if(param_set == "XMSSMT-SHA2_40/8_192") {
      return XMSSMT_SHA2_40_8_192;
   }
   if(param_set == "XMSSMT-SHA2_60/3_192") {
      return XMSSMT_SHA2_60_3_192;
   }
   if(param_set == "XMSSMT-SHA2_60/6_192") {
      return XMSSMT_SHA2_60_6_192;
   }
   if(param_set == "XMSSMT-SHA2_60/12_192") {
      return XMSSMT_SHA2_60_12_192;
   }
   if(param_set == "XMSSMT-SHAKE256_20/2_256") {
      return XMSSMT_SHAKE256_20_2_256;
   }
   if(param_set == "XMSSMT-SHAKE256_20/4_256") {
      return XMSSMT_SHAKE256_20_4_256;
   }
   if(param_set == "XMSSMT-SHAKE256_40/2_256") {
      return XMSSMT_SHAKE256_40_2_256;
   }
   if(param_set == "XMSSMT-SHAKE256_40/4_256") {
      return XMSSMT_SHAKE256_40_4_256;
   }
   if(param_set == "XMSSMT-SHAKE256_40/8_256") {
      return XMSSMT_SHAKE256_40_8_256;
   }
   if(param_set == "XMSSMT-SHAKE256_60/3_256") {
      return XMSSMT_SHAKE256_60_3_256;
   }
   if(param_set == "XMSSMT-SHAKE256_60/6_256") {
      return XMSSMT_SHAKE256_60_6_256;
   }
   if(param_set == "XMSSMT-SHAKE256_60/12_256") {
      return XMSSMT_SHAKE256_60_12_256;
   }
   if(param_set == "XMSSMT-SHAKE256_20/2_192") {
      return XMSSMT_SHAKE256_20_2_192;
   }
   if(param_set == "XMSSMT-SHAKE256_20/4_192") {
      return XMSSMT_SHAKE256_20_4_192;
   }
   if(param_set == "XMSSMT-SHAKE256_40/2_192") {
      return XMSSMT_SHAKE256_40_2_192;
   }
   if(param_set == "XMSSMT-SHAKE256_40/4_192") {
      return XMSSMT_SHAKE256_40_4_192;
   }
   if(param_set == "XMSSMT-SHAKE256_40/8_192") {
      return XMSSMT_SHAKE256_40_8_192;
   }
   if(param_set == "XMSSMT-SHAKE256_60/3_192") {
      return XMSSMT_SHAKE256_60_3_192;
   }
   if(param_set == "XMSSMT-SHAKE256_60/6_192") {
      return XMSSMT_SHAKE256_60_6_192;
   }
   if(param_set == "XMSSMT-SHAKE256_60/12_192") {
      return XMSSMT_SHAKE256_60_12_192;
   }

   throw Lookup_Error(fmt("Unknown XMSS^MT algorithm param '{}'", param_set));
}

std::string_view XMSSMT_Parameters::hash_function_name() const {
   switch(m_oid) {
      case XMSSMT_SHA2_20_2_256:
      case XMSSMT_SHA2_20_4_256:
      case XMSSMT_SHA2_40_2_256:
      case XMSSMT_SHA2_40_4_256:
      case XMSSMT_SHA2_40_8_256:
      case XMSSMT_SHA2_60_3_256:
      case XMSSMT_SHA2_60_6_256:
      case XMSSMT_SHA2_60_12_256:
         return "SHA-256";

      case XMSSMT_SHA2_20_2_512:
      case XMSSMT_SHA2_20_4_512:
      case XMSSMT_SHA2_40_2_512:
      case XMSSMT_SHA2_40_4_512:
      case XMSSMT_SHA2_40_8_512:
      case XMSSMT_SHA2_60_3_512:
      case XMSSMT_SHA2_60_6_512:
      case XMSSMT_SHA2_60_12_512:
         return "SHA-512";

      case XMSSMT_SHAKE_20_2_256:
      case XMSSMT_SHAKE_20_4_256:
      case XMSSMT_SHAKE_40_2_256:
      case XMSSMT_SHAKE_40_4_256:
      case XMSSMT_SHAKE_40_8_256:
      case XMSSMT_SHAKE_60_3_256:
      case XMSSMT_SHAKE_60_6_256:
      case XMSSMT_SHAKE_60_12_256:
         return "SHAKE-128(256)";

      case XMSSMT_SHAKE_20_2_512:
      case XMSSMT_SHAKE_20_4_512:
      case XMSSMT_SHAKE_40_2_512:
      case XMSSMT_SHAKE_40_4_512:
      case XMSSMT_SHAKE_40_8_512:
      case XMSSMT_SHAKE_60_3_512:
      case XMSSMT_SHAKE_60_6_512:
      case XMSSMT_SHAKE_60_12_512:
         return "SHAKE-256(512)";

      case XMSSMT_SHA2_20_2_192:
      case XMSSMT_SHA2_20_4_192:
      case XMSSMT_SHA2_40_2_192:
      case XMSSMT_SHA2_40_4_192:
      case XMSSMT_SHA2_40_8_192:
      case XMSSMT_SHA2_60_3_192:
      case XMSSMT_SHA2_60_6_192:
      case XMSSMT_SHA2_60_12_192:
         return "Truncated(SHA-256,192)";

      case XMSSMT_SHAKE256_20_2_256:
      case XMSSMT_SHAKE256_20_4_256:
      case XMSSMT_SHAKE256_40_2_256:
      case XMSSMT_SHAKE256_40_4_256:
      case XMSSMT_SHAKE256_40_8_256:
      case XMSSMT_SHAKE256_60_3_256:
      case XMSSMT_SHAKE256_60_6_256:
      case XMSSMT_SHAKE256_60_12_256:
         return "SHAKE-256(256)";

      case XMSSMT_SHAKE256_20_2_192:
      case XMSSMT_SHAKE256_20_4_192:
      case XMSSMT_SHAKE256_40_2_192:
      case XMSSMT_SHAKE256_40_4_192:
      case XMSSMT_SHAKE256_40_8_192:
      case XMSSMT_SHAKE256_60_3_192:
      case XMSSMT_SHAKE256_60_6_192:
      case XMSSMT_SHAKE256_60_12_192:
         return "SHAKE-256(192)";

      default:
         BOTAN_ASSERT_UNREACHABLE();
   }
}

std::string_view XMSSMT_Parameters::name() const {
   switch(m_oid) {
      case XMSSMT_SHA2_20_2_256:
         return "XMSSMT-SHA2_20/2_256";

      case XMSSMT_SHA2_20_4_256:
         return "XMSSMT-SHA2_20/4_256";

      case XMSSMT_SHA2_40_2_256:
         return "XMSSMT-SHA2_40/2_256";

      case XMSSMT_SHA2_40_4_256:
         return "XMSSMT-SHA2_40/4_256";

      case XMSSMT_SHA2_40_8_256:
         return "XMSSMT-SHA2_40/8_256";

      case XMSSMT_SHA2_60_3_256:
         return "XMSSMT-SHA2_60/3_256";

      case XMSSMT_SHA2_60_6_256:
         return "XMSSMT-SHA2_60/6_256";

      case XMSSMT_SHA2_60_12_256:
         return "XMSSMT-SHA2_60/12_256";

      case XMSSMT_SHA2_20_2_512:
         return "XMSSMT-SHA2_20/2_512";

      case XMSSMT_SHA2_20_4_512:
         return "XMSSMT-SHA2_20/4_512";

      case XMSSMT_SHA2_40_2_512:
         return "XMSSMT-SHA2_40/2_512";

      case XMSSMT_SHA2_40_4_512:
         return "XMSSMT-SHA2_40/4_512";

      case XMSSMT_SHA2_40_8_512:
         return "XMSSMT-SHA2_40/8_512";

      case XMSSMT_SHA2_60_3_512:
         return "XMSSMT-SHA2_60/3_512";

      case XMSSMT_SHA2_60_6_512:
         return "XMSSMT-SHA2_60/6_512";

      case XMSSMT_SHA2_60_12_512:
         return "XMSSMT-SHA2_60/12_512";

      case XMSSMT_SHAKE_20_2_256:
         return "XMSSMT-SHAKE_20/2_256";

      case XMSSMT_SHAKE_20_4_256:
         return "XMSSMT-SHAKE_20/4_256";

      case XMSSMT_SHAKE_40_2_256:
         return "XMSSMT-SHAKE_40/2_256";

      case XMSSMT_SHAKE_40_4_256:
         return "XMSSMT-SHAKE_40/4_256";

      case XMSSMT_SHAKE_40_8_256:
         return "XMSSMT-SHAKE_40/8_256";

      case XMSSMT_SHAKE_60_3_256:
         return "XMSSMT-SHAKE_60/3_256";

      case XMSSMT_SHAKE_60_6_256:
         return "XMSSMT-SHAKE_60/6_256";

      case XMSSMT_SHAKE_60_12_256:
         return "XMSSMT-SHAKE_60/12_256";

      case XMSSMT_SHAKE_20_2_512:
         return "XMSSMT-SHAKE_20/2_512";

      case XMSSMT_SHAKE_20_4_512:
         return "XMSSMT-SHAKE_20/4_512";

      case XMSSMT_SHAKE_40_2_512:
         return "XMSSMT-SHAKE_40/2_512";

      case XMSSMT_SHAKE_40_4_512:
         return "XMSSMT-SHAKE_40/4_512";

      case XMSSMT_SHAKE_40_8_512:
         return "XMSSMT-SHAKE_40/8_512";

      case XMSSMT_SHAKE_60_3_512:
         return "XMSSMT-SHAKE_60/3_512";

      case XMSSMT_SHAKE_60_6_512:
         return "XMSSMT-SHAKE_60/6_512";

      case XMSSMT_SHAKE_60_12_512:
         return "XMSSMT-SHAKE_60/12_512";

      case XMSSMT_SHA2_20_2_192:
         return "XMSSMT-SHA2_20/2_192";

      case XMSSMT_SHA2_20_4_192:
         return "XMSSMT-SHA2_20/4_192";

      case XMSSMT_SHA2_40_2_192:
         return "XMSSMT-SHA2_40/2_192";

      case XMSSMT_SHA2_40_4_192:
         return "XMSSMT-SHA2_40/4_192";

      case XMSSMT_SHA2_40_8_192:
         return "XMSSMT-SHA2_40/8_192";

      case XMSSMT_SHA2_60_3_192:
         return "XMSSMT-SHA2_60/3_192";

      case XMSSMT_SHA2_60_6_192:
         return "XMSSMT-SHA2_60/6_192";

      case XMSSMT_SHA2_60_12_192:
         return "XMSSMT-SHA2_60/12_192";

      case XMSSMT_SHAKE256_20_2_256:
         return "XMSSMT-SHAKE256_20/2_256";

      case XMSSMT_SHAKE256_20_4_256:
         return "XMSSMT-SHAKE256_20/4_256";

      case XMSSMT_SHAKE256_40_2_256:
         return "XMSSMT-SHAKE256_40/2_256";

      case XMSSMT_SHAKE256_40_4_256:
         return "XMSSMT-SHAKE256_40/4_256";

      case XMSSMT_SHAKE256_40_8_256:
         return "XMSSMT-SHAKE256_40/8_256";

      case XMSSMT_SHAKE256_60_3_256:
         return "XMSSMT-SHAKE256_60/3_256";

      case XMSSMT_SHAKE256_60_6_256:
         return "XMSSMT-SHAKE256_60/6_256";

      case XMSSMT_SHAKE256_60_12_256:
         return "XMSSMT-SHAKE256_60/12_256";

      case XMSSMT_SHAKE256_20_2_192:
         return "XMSSMT-SHAKE256_20/2_192";

      case XMSSMT_SHAKE256_20_4_192:
         return "XMSSMT-SHAKE256_20/4_192";

      case XMSSMT_SHAKE256_40_2_192:
         return "XMSSMT-SHAKE256_40/2_192";

      case XMSSMT_SHAKE256_40_4_192:
         return "XMSSMT-SHAKE256_40/4_192";

      case XMSSMT_SHAKE256_40_8_192:
         return "XMSSMT-SHAKE256_40/8_192";

      case XMSSMT_SHAKE256_60_3_192:
         return "XMSSMT-SHAKE256_60/3_192";

      case XMSSMT_SHAKE256_60_6_192:
         return "XMSSMT-SHAKE256_60/6_192";

      case XMSSMT_SHAKE256_60_12_192:
         return "XMSSMT-SHAKE256_60/12_192";

      default:
         BOTAN_ASSERT_UNREACHABLE();
   }
}

XMSSMT_Parameters XMSSMT_Parameters::from_name(std::string_view param_set) {
   return XMSSMT_Parameters::from_id(XMSSMT_Parameters::xmssmt_id_from_string(param_set));
}

XMSSMT_Parameters XMSSMT_Parameters::from_id(xmssmt_algorithm_t oid) {
   switch(oid) {
      case XMSSMT_SHA2_20_2_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256, 32, 32, 20, 2, 67);

      case XMSSMT_SHA2_20_4_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256, 32, 32, 20, 4, 67);

      case XMSSMT_SHA2_40_2_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256, 32, 32, 40, 2, 67);

      case XMSSMT_SHA2_40_4_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256, 32, 32, 40, 4, 67);

      case XMSSMT_SHA2_40_8_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256, 32, 32, 40, 8, 67);

      case XMSSMT_SHA2_60_3_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256, 32, 32, 60, 3, 67);

      case XMSSMT_SHA2_60_6_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256, 32, 32, 60, 6, 67);

      case XMSSMT_SHA2_60_12_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256, 32, 32, 60, 12, 67);

      case XMSSMT_SHA2_20_2_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512, 64, 64, 20, 2, 131);

      case XMSSMT_SHA2_20_4_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512, 64, 64, 20, 4, 131);

      case XMSSMT_SHA2_40_2_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512, 64, 64, 40, 2, 131);

      case XMSSMT_SHA2_40_4_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512, 64, 64, 40, 4, 131);

      case XMSSMT_SHA2_40_8_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512, 64, 64, 40, 8, 131);

      case XMSSMT_SHA2_60_3_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512, 64, 64, 60, 3, 131);

      case XMSSMT_SHA2_60_6_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512, 64, 64, 60, 6, 131);

      case XMSSMT_SHA2_60_12_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512, 64, 64, 60, 12, 131);

      case XMSSMT_SHAKE_20_2_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256, 32, 32, 20, 2, 67);

      case XMSSMT_SHAKE_20_4_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256, 32, 32, 20, 4, 67);

      case XMSSMT_SHAKE_40_2_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256, 32, 32, 40, 2, 67);

      case XMSSMT_SHAKE_40_4_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256, 32, 32, 40, 4, 67);

      case XMSSMT_SHAKE_40_8_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256, 32, 32, 40, 8, 67);

      case XMSSMT_SHAKE_60_3_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256, 32, 32, 60, 3, 67);

      case XMSSMT_SHAKE_60_6_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256, 32, 32, 60, 6, 67);

      case XMSSMT_SHAKE_60_12_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256, 32, 32, 60, 12, 67);

      case XMSSMT_SHAKE_20_2_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512, 64, 64, 20, 2, 131);

      case XMSSMT_SHAKE_20_4_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512, 64, 64, 20, 4, 131);

      case XMSSMT_SHAKE_40_2_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512, 64, 64, 40, 2, 131);

      case XMSSMT_SHAKE_40_4_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512, 64, 64, 40, 4, 131);

      case XMSSMT_SHAKE_40_8_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512, 64, 64, 40, 8, 131);

      case XMSSMT_SHAKE_60_3_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512, 64, 64, 60, 3, 131);

      case XMSSMT_SHAKE_60_6_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512, 64, 64, 60, 6, 131);

      case XMSSMT_SHAKE_60_12_512:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512, 64, 64, 60, 12, 131);

      case XMSSMT_SHA2_20_2_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192, 24, 4, 20, 2, 51);

      case XMSSMT_SHA2_20_4_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192, 24, 4, 20, 4, 51);

      case XMSSMT_SHA2_40_2_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192, 24, 4, 40, 2, 51);

      case XMSSMT_SHA2_40_4_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192, 24, 4, 40, 4, 51);

      case XMSSMT_SHA2_40_8_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192, 24, 4, 40, 8, 51);

      case XMSSMT_SHA2_60_3_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192, 24, 4, 60, 3, 51);

      case XMSSMT_SHA2_60_6_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192, 24, 4, 60, 6, 51);

      case XMSSMT_SHA2_60_12_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192, 24, 4, 60, 12, 51);

      case XMSSMT_SHAKE256_20_2_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256, 32, 32, 20, 2, 67);

      case XMSSMT_SHAKE256_20_4_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256, 32, 32, 20, 4, 67);

      case XMSSMT_SHAKE256_40_2_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256, 32, 32, 40, 2, 67);

      case XMSSMT_SHAKE256_40_4_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256, 32, 32, 40, 4, 67);

      case XMSSMT_SHAKE256_40_8_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256, 32, 32, 40, 8, 67);

      case XMSSMT_SHAKE256_60_3_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256, 32, 32, 60, 3, 67);

      case XMSSMT_SHAKE256_60_6_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256, 32, 32, 60, 6, 67);

      case XMSSMT_SHAKE256_60_12_256:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256, 32, 32, 60, 12, 67);

      case XMSSMT_SHAKE256_20_2_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192, 24, 4, 20, 2, 51);

      case XMSSMT_SHAKE256_20_4_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192, 24, 4, 20, 4, 51);

      case XMSSMT_SHAKE256_40_2_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192, 24, 4, 40, 2, 51);

      case XMSSMT_SHAKE256_40_4_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192, 24, 4, 40, 4, 51);

      case XMSSMT_SHAKE256_40_8_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192, 24, 4, 40, 8, 51);

      case XMSSMT_SHAKE256_60_3_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192, 24, 4, 60, 3, 51);

      case XMSSMT_SHAKE256_60_6_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192, 24, 4, 60, 6, 51);

      case XMSSMT_SHAKE256_60_12_192:
         return XMSSMT_Parameters(oid, XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192, 24, 4, 60, 12, 51);

      default:
         throw Not_Implemented("Algorithm id does not match any known XMSS^MT algorithm id:" + std::to_string(oid));
   }
}

}  // namespace Botan
