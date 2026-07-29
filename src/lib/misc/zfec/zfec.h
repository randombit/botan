/*
 * Forward error correction based on Vandermonde matrices
 *
 * (C) 1997-1998 Luigi Rizzo (luigi@iet.unipi.it)
 * (C) 2009,2017,2021 Jack Lloyd
 *
 * Distributed under the terms given in license.txt
 */

#ifndef BOTAN_ZFEC_H_
#define BOTAN_ZFEC_H_

#include <botan/types.h>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace Botan {

/**
* A forward error correction code compatible with the zfec
* library (https://github.com/tahoe-lafs/zfec)
*
* This algorithm is *not constant time* and is likely susceptible to
* side channels. Do not use this class to encode information that
* should be kept secret. (If nothing else, because the first K shares
* are simply the original input!)
*/
class BOTAN_PUBLIC_API(3, 0) ZFEC final {
   public:
      /**
      * Callback invoked with each produced share
      *
      * Receives the share index, a pointer to the share contents, and the
      * length of the share in bytes.
      */
      typedef std::function<void(size_t, const uint8_t[], size_t)> output_cb_t;

      /**
      * FEC constructor
      * @param K the number of shares needed for recovery
      * @param N the number of shares generated
      */
      ZFEC(size_t K, size_t N);

      /**
      * Return how many shares are needed for recovery
      * @return the value of K
      */
      size_t recovery_threshold() const { return m_K; }

      /**
      * Return how many shares are generated
      * @return the value of N
      */
      size_t generated_shares() const { return m_N; }

      /**
      * Return the name of the provider implementing this object
      * @return the provider name
      */
      std::string provider() const;

      /**
      * Encode the input into N shares
      * @param input the data to FEC
      * @param size the length in bytes of input
      * @param output_cb the output callback
      */
      void encode(const uint8_t input[], size_t size, const output_cb_t& output_cb) const;

      /**
      * Encode K existing shares into N shares
      * @param shares exactly K shares of data to FEC
      * @param share_size the length in bytes of each share
      * @param output_cb the output callback
      */
      void encode_shares(const std::vector<const uint8_t*>& shares,
                         size_t share_size,
                         const output_cb_t& output_cb) const;

      /**
      * Recover the original data from K shares
      * @param shares map of share id to share contents
      * @param share_size size in bytes of each share
      * @param output_cb the output callback
      */
      void decode_shares(const std::map<size_t, const uint8_t*>& shares,
                         size_t share_size,
                         const output_cb_t& output_cb) const;

   private:
      static void addmul(uint8_t z[], const uint8_t x[], uint8_t y, size_t size);

      static void linear_combination(uint8_t z[], const uint8_t* const x[], const uint8_t y[], size_t k, size_t size);

#if defined(BOTAN_HAS_ZFEC_VPERM)
      static size_t linear_combination_vperm(
         uint8_t z[], const uint8_t* const x[], const uint8_t y[], size_t k, size_t size);
#endif

#if defined(BOTAN_HAS_ZFEC_GFNI)
      static void linear_combination_gfni(
         uint8_t z[], const uint8_t* const x[], const uint8_t y[], size_t k, size_t size);
#endif

      const size_t m_K, m_N;
      std::vector<uint8_t> m_enc_matrix;
};

}  // namespace Botan

#endif
