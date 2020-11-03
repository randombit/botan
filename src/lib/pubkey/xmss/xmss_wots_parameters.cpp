/*
 * XMSS WOTS Parameters
 * Descibes a signature method for XMSS Winternitz One Time Signatures,
 * as defined in:
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 *
 * (C) 2016,2017,2018 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss_wots.h>
#include <botan/internal/xmss_tools.h>
#include <botan/exceptn.h>
#include <cmath>

namespace Botan {

XMSS_WOTS_Parameters::ots_algorithm_t
XMSS_WOTS_Parameters::xmss_wots_id_from_string(const std::string& param_set)
   {
   if(param_set == "WOTSP-SHA2_256")
      { return WOTSP_SHA2_256; }
   if(param_set == "WOTSP-SHA2_512")
      { return WOTSP_SHA2_512; }
   if(param_set == "WOTSP-SHAKE_256")
      { return WOTSP_SHAKE_256; }
   if(param_set == "WOTSP-SHAKE_512")
      { return WOTSP_SHAKE_512; }
   throw Invalid_Argument("Unknown XMSS-WOTS algorithm param '" + param_set + "'");
   }

XMSS_WOTS_Parameters::XMSS_WOTS_Parameters(const std::string& param_set)
   : XMSS_WOTS_Parameters(xmss_wots_id_from_string(param_set))
   {}

XMSS_WOTS_Parameters::XMSS_WOTS_Parameters(ots_algorithm_t oid)
   : m_oid(oid)
   {
   switch(oid)
      {
      case WOTSP_SHA2_256:
         m_element_size = 32;
         m_w = 16;
         m_len = 67;
         m_name = "WOTSP-SHA2_256";
         m_hash_name = "SHA-256";
         m_strength = 256;
         break;
      case WOTSP_SHA2_512:
         m_element_size = 64;
         m_w = 16;
         m_len = 131;
         m_name = "WOTSP-SHA2_512";
         m_hash_name = "SHA-512";
         m_strength = 512;
         break;
      case WOTSP_SHAKE_256:
         m_element_size = 32;
         m_w = 16;
         m_len = 67;
         m_name = "WOTSP-SHAKE_256";
         m_hash_name = "SHAKE-128(256)";
         m_strength = 256;
         break;
      case WOTSP_SHAKE_512:
         m_element_size = 64;
         m_w = 16;
         m_len = 131;
         m_name = "WOTSP-SHAKE_512";
         m_hash_name = "SHAKE-256(512)";
         m_strength = 512;
         break;
      default:
         throw Not_Implemented("Algorithm id does not match any known XMSS WOTS algorithm id.");
         break;
      }

   m_lg_w = (m_w == 16) ? 4 : 2;
   m_len_1 = static_cast<size_t>(std::ceil((8 * element_size()) / m_lg_w));
   m_len_2 = static_cast<size_t>(
                floor(log2(m_len_1 * (wots_parameter() - 1)) / m_lg_w) + 1);
   BOTAN_ASSERT(m_len == m_len_1 + m_len_2, "Invalid XMSS WOTS parameter "
                "\"len\" detedted.");
   }

secure_vector<uint8_t>
XMSS_WOTS_Parameters::base_w(const secure_vector<uint8_t>& msg, size_t out_size) const
   {
   secure_vector<uint8_t> result;
   size_t in = 0;
   size_t total = 0;
   size_t bits = 0;

   for(size_t i = 0; i < out_size; i++)
      {
      if(bits == 0)
         {
         total = msg[in];
         in++;
         bits += 8;
         }
      bits -= m_lg_w;
      result.push_back(static_cast<uint8_t>((total >> bits) & (m_w - 1)));
      }
   return result;
   }

secure_vector<uint8_t>
XMSS_WOTS_Parameters::base_w(size_t value) const
   {
   value <<= (8 - ((m_len_2 * m_lg_w) % 8));
   size_t len_2_bytes = static_cast<size_t>(
                           std::ceil(static_cast<float>(m_len_2 * m_lg_w) / 8.f));
   secure_vector<uint8_t> result;
   XMSS_Tools::concat(result, value, len_2_bytes);
   return base_w(result, m_len_2);
   }

void
XMSS_WOTS_Parameters::append_checksum(secure_vector<uint8_t>& data)
   {
   size_t csum = 0;

   for(size_t i = 0; i < data.size(); i++)
      {
      csum += wots_parameter() - 1 - data[i];
      }

   secure_vector<uint8_t> csum_bytes = base_w(csum);
   std::move(csum_bytes.begin(), csum_bytes.end(), std::back_inserter(data));
   }

}
