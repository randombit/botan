/*
 * XMSS Parameters
 * (C) 2016,2018 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_WOTS_PARAMETERS_H_
#define BOTAN_XMSS_WOTS_PARAMETERS_H_

#include <map>
#include <string>

#include <botan/secmem.h>
#include <botan/types.h>

namespace Botan {

/**
 * Describes a signature method for XMSS Winternitz One Time Signatures,
 * as defined in:
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 * [2] Recommendation for Stateful Hash-Based Signature Schemes
 *     NIST Special Publication 800-208
 *     Release: October 2020.
 *     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf
 **/
class BOTAN_PUBLIC_API(2, 0) XMSS_WOTS_Parameters final {
   public:
      enum ots_algorithm_t : uint32_t /* NOLINT(*-enum-size,*-use-enum-class) */ {
         // from RFC 8391
         WOTSP_SHA2_256 = 0x00000001,

         // from RFC 8391 but not approved by NIST SP.800-208
         // (see footnote on page 16)
         WOTSP_SHA2_512 = 0x00000002,
         WOTSP_SHAKE_256 = 0x00000003,
         WOTSP_SHAKE_512 = 0x00000004,

         // from NIST SP.800-208
         WOTSP_SHA2_192 = 0x00000005,
         WOTSP_SHAKE_256_256 = 0x00000006,
         WOTSP_SHAKE_256_192 = 0x00000007,
      };

      explicit XMSS_WOTS_Parameters(std::string_view algo_name);

      BOTAN_FUTURE_EXPLICIT XMSS_WOTS_Parameters(ots_algorithm_t ots_spec);

      static ots_algorithm_t xmss_wots_id_from_string(std::string_view param_set);

      /**
       * Algorithm 1: convert input string to base.
       *
       * @param msg Input string (referred to as X in [1]).
       * @param out_size size of message in base w.
       *
       * @return Input string converted to the given base.
       **/
      secure_vector<uint8_t> base_w(const secure_vector<uint8_t>& msg, size_t out_size) const;

      secure_vector<uint8_t> base_w(size_t value) const;

      void append_checksum(secure_vector<uint8_t>& data) const;

      /**
       * @return XMSS WOTS registry name for the chosen parameter set.
       **/
      const std::string& name() const { return m_name; }

      /**
       * Retrieves the uniform length of a message, and the size of
       * each node. This correlates to XMSS parameter "n" defined
       * in [1].
       *
       * @return element length in bytes.
       **/
      size_t element_size() const { return m_element_size; }

      /**
       * The Winternitz parameter.
       *
       * @return numeric base used for internal representation of
       *         data.
       **/
      size_t wots_parameter() const { return m_w; }

      size_t len() const { return m_len; }

      size_t len_1() const { return m_len_1; }

      size_t len_2() const { return m_len_2; }

      size_t lg_w() const { return m_lg_w; }

      ots_algorithm_t oid() const { return m_oid; }

      size_t estimated_strength() const { return m_strength; }

      bool operator==(const XMSS_WOTS_Parameters& p) const { return m_oid == p.m_oid; }

   private:
      static const std::map<std::string, ots_algorithm_t> m_oid_name_lut;
      ots_algorithm_t m_oid;
      std::string m_name;
      std::string m_hash_name;
      size_t m_element_size;
      size_t m_w;
      size_t m_len_1;
      size_t m_len_2;
      size_t m_len;
      size_t m_strength;
      uint8_t m_lg_w;
};

}  // namespace Botan

#endif
