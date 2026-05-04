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

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

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

XMSSMT_Parameters::xmssmt_algorithm_t XMSSMT_Parameters::parse_oid(std::span<const uint8_t> bytes) {
   if(bytes.size() != 4) {
      throw Decoding_Error("can't parse invalid XMSS^MT OID length.");
   }

   // extract and convert algorithm id to enum type
   uint32_t raw_id = 0;
   for(size_t i = 0; i < 4; i++) {
      raw_id = ((raw_id << 8) | bytes[i]);
   }
   return static_cast<XMSSMT_Parameters::xmssmt_algorithm_t>(raw_id);
}

XMSSMT_Parameters::XMSSMT_Parameters(std::string_view param_set) :
      XMSSMT_Parameters(XMSSMT_Parameters::xmssmt_id_from_string(param_set)) {}

XMSSMT_Parameters::XMSSMT_Parameters(xmssmt_algorithm_t oid) : m_oid(oid) {
   switch(oid) {
      case XMSSMT_SHA2_20_2_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 20;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHA2_20/2_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSSMT_SHA2_20_4_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 20;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHA2_20/4_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSSMT_SHA2_40_2_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHA2_40/2_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSSMT_SHA2_40_4_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHA2_40/4_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSSMT_SHA2_40_8_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 8;
         m_name = "XMSSMT-SHA2_40/8_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSSMT_SHA2_60_3_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 3;
         m_name = "XMSSMT-SHA2_60/3_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSSMT_SHA2_60_6_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 6;
         m_name = "XMSSMT-SHA2_60/6_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSSMT_SHA2_60_12_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 12;
         m_name = "XMSSMT-SHA2_60/12_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSSMT_SHA2_20_2_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 20;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHA2_20/2_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSSMT_SHA2_20_4_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 20;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHA2_20/4_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSSMT_SHA2_40_2_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 40;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHA2_40/2_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSSMT_SHA2_40_4_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 40;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHA2_40/4_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSSMT_SHA2_40_8_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 40;
         m_tree_layers = 8;
         m_name = "XMSSMT-SHA2_40/8_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSSMT_SHA2_60_3_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 60;
         m_tree_layers = 3;
         m_name = "XMSSMT-SHA2_60/3_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSSMT_SHA2_60_6_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 60;
         m_tree_layers = 6;
         m_name = "XMSSMT-SHA2_60/6_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSSMT_SHA2_60_12_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 60;
         m_tree_layers = 12;
         m_name = "XMSSMT-SHA2_60/12_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSSMT_SHAKE_20_2_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 20;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHAKE_20/2_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSSMT_SHAKE_20_4_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 20;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHAKE_20/4_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSSMT_SHAKE_40_2_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHAKE_40/2_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSSMT_SHAKE_40_4_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHAKE_40/4_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSSMT_SHAKE_40_8_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 8;
         m_name = "XMSSMT-SHAKE_40/8_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSSMT_SHAKE_60_3_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 3;
         m_name = "XMSSMT-SHAKE_60/3_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSSMT_SHAKE_60_6_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 6;
         m_name = "XMSSMT-SHAKE_60/6_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSSMT_SHAKE_60_12_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 12;
         m_name = "XMSSMT-SHAKE_60/12_256";
         m_hash_name = "SHAKE-128(256)6";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSSMT_SHAKE_20_2_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 20;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHAKE_20/2_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSSMT_SHAKE_20_4_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 20;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHAKE_20/4_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSSMT_SHAKE_40_2_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 40;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHAKE_40/2_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSSMT_SHAKE_40_4_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 40;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHAKE_40/4_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSSMT_SHAKE_40_8_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 40;
         m_tree_layers = 8;
         m_name = "XMSSMT-SHAKE_40/8_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSSMT_SHAKE_60_3_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 60;
         m_tree_layers = 3;
         m_name = "XMSSMT-SHAKE_60/3_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSSMT_SHAKE_60_6_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 60;
         m_tree_layers = 6;
         m_name = "XMSSMT-SHAKE_60/6_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSSMT_SHAKE_60_12_512:
         m_element_size = 64;
         m_hash_id_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 60;
         m_tree_layers = 12;
         m_name = "XMSSMT-SHAKE_60/12_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSSMT_SHA2_20_2_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 20;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHA2_20/2_192";
         m_hash_name = "Truncated(SHA-256,192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192;
         break;
      case XMSSMT_SHA2_20_4_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 20;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHA2_20/4_192";
         m_hash_name = "Truncated(SHA-256,192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192;
         break;
      case XMSSMT_SHA2_40_2_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 40;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHA2_40/2_192";
         m_hash_name = "Truncated(SHA-256,192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192;
         break;
      case XMSSMT_SHA2_40_4_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 40;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHA2_40/4_192";
         m_hash_name = "Truncated(SHA-256,192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192;
         break;
      case XMSSMT_SHA2_40_8_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 40;
         m_tree_layers = 8;
         m_name = "XMSSMT-SHA2_40/8_192";
         m_hash_name = "Truncated(SHA-256,192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192;
         break;
      case XMSSMT_SHA2_60_3_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 60;
         m_tree_layers = 3;
         m_name = "XMSSMT-SHA2_60/3_192";
         m_hash_name = "Truncated(SHA-256,192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192;
         break;
      case XMSSMT_SHA2_60_6_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 60;
         m_tree_layers = 6;
         m_name = "XMSSMT-SHA2_60/6_192";
         m_hash_name = "Truncated(SHA-256,192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192;
         break;
      case XMSSMT_SHA2_60_12_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 60;
         m_tree_layers = 12;
         m_name = "XMSSMT-SHA2_60/12_192";
         m_hash_name = "Truncated(SHA-256,192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_192;
         break;
      case XMSSMT_SHAKE256_20_2_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 20;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHAKE256_20/2_256";
         m_hash_name = "SHAKE-256(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256;
         break;
      case XMSSMT_SHAKE256_20_4_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 20;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHAKE256_20/4_256";
         m_hash_name = "SHAKE-256(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256;
         break;
      case XMSSMT_SHAKE256_40_2_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHAKE256_40/2_256";
         m_hash_name = "SHAKE-256(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256;
         break;
      case XMSSMT_SHAKE256_40_4_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHAKE256_40/4_256";
         m_hash_name = "SHAKE-256(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256;
         break;
      case XMSSMT_SHAKE256_40_8_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 40;
         m_tree_layers = 8;
         m_name = "XMSSMT-SHAKE256_40/8_256";
         m_hash_name = "SHAKE-256(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256;
         break;
      case XMSSMT_SHAKE256_60_3_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 3;
         m_name = "XMSSMT-SHAKE256_60/3_256";
         m_hash_name = "SHAKE-256(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256;
         break;
      case XMSSMT_SHAKE256_60_6_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 6;
         m_name = "XMSSMT-SHAKE256_60/6_256";
         m_hash_name = "SHAKE-256(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256;
         break;
      case XMSSMT_SHAKE256_60_12_256:
         m_element_size = 32;
         m_hash_id_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 60;
         m_tree_layers = 12;
         m_name = "XMSSMT-SHAKE256_60/12_256";
         m_hash_name = "SHAKE-256(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_256;
         break;
      case XMSSMT_SHAKE256_20_2_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 20;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHAKE256_20/2_192";
         m_hash_name = "SHAKE-256(192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192;
         break;
      case XMSSMT_SHAKE256_20_4_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 20;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHAKE256_20/4_192";
         m_hash_name = "SHAKE-256(192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192;
         break;
      case XMSSMT_SHAKE256_40_2_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 40;
         m_tree_layers = 2;
         m_name = "XMSSMT-SHAKE256_40/2_192";
         m_hash_name = "SHAKE-256(192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192;
         break;
      case XMSSMT_SHAKE256_40_4_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 40;
         m_tree_layers = 4;
         m_name = "XMSSMT-SHAKE256_40/4_192";
         m_hash_name = "SHAKE-256(192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192;
         break;
      case XMSSMT_SHAKE256_40_8_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 40;
         m_tree_layers = 8;
         m_name = "XMSSMT-SHAKE256_40/8_192";
         m_hash_name = "SHAKE-256(192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192;
         break;
      case XMSSMT_SHAKE256_60_3_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 60;
         m_tree_layers = 3;
         m_name = "XMSSMT-SHAKE256_60/3_192";
         m_hash_name = "SHAKE-256(192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192;
         break;
      case XMSSMT_SHAKE256_60_6_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 60;
         m_tree_layers = 6;
         m_name = "XMSSMT-SHAKE256_60/6_192";
         m_hash_name = "SHAKE-256(192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192;
         break;
      case XMSSMT_SHAKE256_60_12_192:
         m_element_size = 24;
         m_hash_id_size = 4;
         m_w = 16;
         m_len = 51;
         m_tree_height = 60;
         m_tree_layers = 12;
         m_name = "XMSSMT-SHAKE256_60/12_192";
         m_hash_name = "SHAKE-256(192)";
         m_strength = 192;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256_192;
         break;
      default:
         throw Not_Implemented("Algorithm id does not match any known XMSS^MT algorithm id:" + std::to_string(oid));
   }
}
}  // namespace Botan
