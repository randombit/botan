/*
 * XMSS^MT Parameters
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSSMT_PARAMETERS_H_
#define BOTAN_XMSSMT_PARAMETERS_H_

#include <botan/secmem.h>
#include <botan/types.h>
#include <botan/xmss_wots_parameters.h>
#include <string>

namespace Botan {

/**
 * Describes a signature method for XMSS^MT, as defined in:
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 * [2] Recommendation for Stateful Hash-Based Signature Schemes
 *     NIST Special Publication 800-208
 *     Release: October 2020.
 *     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf
 **/
class BOTAN_PUBLIC_API(3, 12) XMSSMT_Parameters {
   public:
      enum xmssmt_algorithm_t : uint32_t /* NOLINT(*-enum-size,*-use-enum-class) */ {
         // from RFC 8391
         XMSSMT_SHA2_20_2_256 = 0x00000001,
         XMSSMT_SHA2_20_4_256 = 0x00000002,
         XMSSMT_SHA2_40_2_256 = 0x00000003,
         XMSSMT_SHA2_40_4_256 = 0x00000004,
         XMSSMT_SHA2_40_8_256 = 0x00000005,
         XMSSMT_SHA2_60_3_256 = 0x00000006,
         XMSSMT_SHA2_60_6_256 = 0x00000007,
         XMSSMT_SHA2_60_12_256 = 0x00000008,

         // from RFC 8391 but not approved by NIST SP.800-208
         // (see footnote on page 16)
         XMSSMT_SHA2_20_2_512 = 0x00000009,
         XMSSMT_SHA2_20_4_512 = 0x0000000a,
         XMSSMT_SHA2_40_2_512 = 0x0000000b,
         XMSSMT_SHA2_40_4_512 = 0x0000000c,
         XMSSMT_SHA2_40_8_512 = 0x0000000d,
         XMSSMT_SHA2_60_3_512 = 0x0000000e,
         XMSSMT_SHA2_60_6_512 = 0x0000000f,
         XMSSMT_SHA2_60_12_512 = 0x00000010,
         XMSSMT_SHAKE_20_2_256 = 0x00000011,
         XMSSMT_SHAKE_20_4_256 = 0x00000012,
         XMSSMT_SHAKE_40_2_256 = 0x00000013,
         XMSSMT_SHAKE_40_4_256 = 0x00000014,
         XMSSMT_SHAKE_40_8_256 = 0x00000015,
         XMSSMT_SHAKE_60_3_256 = 0x00000016,
         XMSSMT_SHAKE_60_6_256 = 0x00000017,
         XMSSMT_SHAKE_60_12_256 = 0x00000018,
         XMSSMT_SHAKE_20_2_512 = 0x00000019,
         XMSSMT_SHAKE_20_4_512 = 0x0000001a,
         XMSSMT_SHAKE_40_2_512 = 0x0000001b,
         XMSSMT_SHAKE_40_4_512 = 0x0000001c,
         XMSSMT_SHAKE_40_8_512 = 0x0000001d,
         XMSSMT_SHAKE_60_3_512 = 0x0000001e,
         XMSSMT_SHAKE_60_6_512 = 0x0000001f,
         XMSSMT_SHAKE_60_12_512 = 0x00000020,

         // from NIST SP800-208
         XMSSMT_SHA2_20_2_192 = 0x00000021,
         XMSSMT_SHA2_20_4_192 = 0x00000022,
         XMSSMT_SHA2_40_2_192 = 0x00000023,
         XMSSMT_SHA2_40_4_192 = 0x00000024,
         XMSSMT_SHA2_40_8_192 = 0x00000025,
         XMSSMT_SHA2_60_3_192 = 0x00000026,
         XMSSMT_SHA2_60_6_192 = 0x00000027,
         XMSSMT_SHA2_60_12_192 = 0x00000028,
         XMSSMT_SHAKE256_20_2_256 = 0x00000029,
         XMSSMT_SHAKE256_20_4_256 = 0x0000002a,
         XMSSMT_SHAKE256_40_2_256 = 0x0000002b,
         XMSSMT_SHAKE256_40_4_256 = 0x0000002c,
         XMSSMT_SHAKE256_40_8_256 = 0x0000002d,
         XMSSMT_SHAKE256_60_3_256 = 0x0000002e,
         XMSSMT_SHAKE256_60_6_256 = 0x0000002f,
         XMSSMT_SHAKE256_60_12_256 = 0x00000030,
         XMSSMT_SHAKE256_20_2_192 = 0x00000031,
         XMSSMT_SHAKE256_20_4_192 = 0x00000032,
         XMSSMT_SHAKE256_40_2_192 = 0x00000033,
         XMSSMT_SHAKE256_40_4_192 = 0x00000034,
         XMSSMT_SHAKE256_40_8_192 = 0x00000035,
         XMSSMT_SHAKE256_60_3_192 = 0x00000036,
         XMSSMT_SHAKE256_60_6_192 = 0x00000037,
         XMSSMT_SHAKE256_60_12_192 = 0x00000038
      };

      static xmssmt_algorithm_t xmssmt_id_from_string(std::string_view algo_name);

      explicit XMSSMT_Parameters(std::string_view algo_name);
      explicit XMSSMT_Parameters(xmssmt_algorithm_t oid);

      /**
       * @return XMSS^MT registry name for the chosen parameter set.
       **/
      const std::string& name() const { return m_name; }

      const std::string& hash_function_name() const { return m_hash_name; }

      /**
       * Retrieves the uniform length of a message, and the size of
       * each node. This correlates to XMSS^MT parameter "n" defined
       * in [1].
       *
       * @return element length in bytes.
       **/
      size_t element_size() const { return m_element_size; }

      /**
       * Retrieves the length of the hash identifier (domain separator)
       * in bytes. See definition of `toByte()` in RFC 8391 Section 2.4
       * and the concrete definitions of hash functions in Section 5.1
       * where this parameter is always equal to the output length of the
       * underlying hash primitive. Also see NIST SP.800-208 where
       * instantiations utilizing truncated hashes use shorter hash IDs.
       */
      size_t hash_id_size() const { return m_hash_id_size; }

      /**
       * @returns The total height (number of levels - 1) of the tree
       **/
      size_t tree_height() const { return m_tree_height; }

      /**
       * @returns The height of one XMSS tree in the XMSS^MT hyper tree.
       **/
      size_t xmss_tree_height() const {
         // Note: All layers are of equal height, i.e., the total height is guaranteed to be divisible by the number of layers.
         return m_tree_height / m_tree_layers;
      }

      /**
       * @returns The size of the encoded index value in an XMSS^MT signatures and keys (at most 8 bytes).
       **/
      size_t encoded_idx_size() const { return (m_tree_height + 7) / 8; }  // ceil(h/8)

      /**
       * @returns The number of layers in the hypertree
       **/
      size_t tree_layers() const { return m_tree_layers; }

      /**
       * @returns total number of signatures allowed for this XMSS^MT instance
       */
      uint64_t total_number_of_signatures() const { return uint64_t(1) << tree_height(); }

      /**
       * The Winternitz parameter.
       *
       * @return numeric base used for internal representation of
       *         data.
       **/
      size_t wots_parameter() const { return m_w; }

      size_t len() const { return m_len; }

      xmssmt_algorithm_t oid() const { return m_oid; }

      XMSS_WOTS_Parameters::ots_algorithm_t ots_oid() const { return m_wots_oid; }

      /**
       * Returns the estimated pre-quantum security level of
       * the chosen algorithm.
       **/
      size_t estimated_strength() const { return m_strength; }

      size_t raw_public_key_size() const { return sizeof(uint32_t) + 2 * element_size(); }

      size_t raw_private_key_size() const { return raw_public_key_size() + encoded_idx_size() + 2 * element_size(); }

      bool operator==(const XMSSMT_Parameters& p) const { return m_oid == p.m_oid; }

   private:
      xmssmt_algorithm_t m_oid;
      XMSS_WOTS_Parameters::ots_algorithm_t m_wots_oid;
      std::string m_name;
      std::string m_hash_name;
      size_t m_element_size;
      size_t m_hash_id_size;
      size_t m_tree_height;
      size_t m_tree_layers;
      size_t m_w;
      size_t m_len;
      size_t m_strength;
};

}  // namespace Botan

#endif
