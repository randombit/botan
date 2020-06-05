/*
 * XMSS Parameters
 * Descibes a signature method for XMSS, as defined in:
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 *
 * (C) 2016,2017,2018 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss_parameters.h>
#include <botan/exceptn.h>

namespace Botan {

XMSS_Parameters::xmss_algorithm_t XMSS_Parameters::xmss_id_from_string(const std::string& param_set)
   {
   if(param_set == "XMSS-SHA2_10_256")
      { return XMSS_SHA2_10_256; }
   if(param_set == "XMSS-SHA2_16_256")
      { return XMSS_SHA2_16_256; }
   if(param_set == "XMSS-SHA2_20_256")
      { return XMSS_SHA2_20_256; }
   if(param_set == "XMSS-SHA2_10_512")
      { return XMSS_SHA2_10_512; }
   if(param_set == "XMSS-SHA2_16_512")
      { return XMSS_SHA2_16_512; }
   if(param_set == "XMSS-SHA2_20_512")
      { return XMSS_SHA2_20_512; }
   if(param_set == "XMSS-SHAKE_10_256")
      { return XMSS_SHAKE_10_256; }
   if(param_set == "XMSS-SHAKE_16_256")
      { return XMSS_SHAKE_16_256; }
   if(param_set == "XMSS-SHAKE_20_256")
      { return XMSS_SHAKE_20_256; }
   if(param_set == "XMSS-SHAKE_10_512")
      { return XMSS_SHAKE_10_512; }
   if(param_set == "XMSS-SHAKE_16_512")
      { return XMSS_SHAKE_16_512; }
   if(param_set == "XMSS-SHAKE_20_512")
      { return XMSS_SHAKE_20_512; }
   throw Lookup_Error("Unknown XMSS algorithm param '" + param_set + "'");
   }

XMSS_Parameters::XMSS_Parameters(const std::string& param_set)
   : XMSS_Parameters(XMSS_Parameters::xmss_id_from_string(param_set))
   {
   }

XMSS_Parameters::XMSS_Parameters(xmss_algorithm_t oid)
   : m_oid(oid)
   {
   switch(oid)
      {
      case XMSS_SHA2_10_256:
         m_element_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 10;
         m_name = "XMSS-SHA2_10_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSS_SHA2_16_256:
         m_element_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 16;
         m_name = "XMSS-SHA2_16_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSS_SHA2_20_256:
         m_element_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 20;
         m_name = "XMSS-SHA2_20_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_256;
         break;
      case XMSS_SHA2_10_512:
         m_element_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 10;
         m_name = "XMSS-SHA2_10_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSS_SHA2_16_512:
         m_element_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 16;
         m_name = "XMSS-SHA2_16_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSS_SHA2_20_512:
         m_element_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 20;
         m_name = "XMSS-SHA2_20_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHA2_512;
         break;
      case XMSS_SHAKE_10_256:
         m_element_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 10;
         m_name = "XMSS-SHAKE_10_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSS_SHAKE_16_256:
         m_element_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 16;
         m_name = "XMSS-SHAKE_16_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSS_SHAKE_20_256:
         m_element_size = 32;
         m_w = 16;
         m_len = 67;
         m_tree_height = 20;
         m_name = "XMSS-SHAKE_20_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_256;
         break;
      case XMSS_SHAKE_10_512:
         m_element_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 10;
         m_name = "XMSS-SHAKE_10_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSS_SHAKE_16_512:
         m_element_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 16;
         m_name = "XMSS-SHAKE_16_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      case XMSS_SHAKE_20_512:
         m_element_size = 64;
         m_w = 16;
         m_len = 131;
         m_tree_height = 20;
         m_name = "XMSS-SHAKE_20_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         m_wots_oid = XMSS_WOTS_Parameters::ots_algorithm_t::WOTSP_SHAKE_512;
         break;
      default:
         throw Not_Implemented("Algorithm id does not match any known XMSS algorithm id:" + std::to_string(oid));
         break;
      }
   }

}
