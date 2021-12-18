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
#include <string>
#include <map>
#include <vector>
#include <functional>

namespace Botan {

/**
* A forward error correction code compatible with the zfec
* library (https://github.com/tahoe-lafs/zfec)
*
* This algorithm is *not constant time* and is likely succeptible to
* side channels. Do not use this class to encode information that
* should be kept secret. (If nothing else, because the first K shares
* are simply the original input!)
*/
class BOTAN_PUBLIC_API(3,0) ZFEC
   {
   public:
      /**
      * FEC constructor
      * @param K the number of shares needed for recovery
      * @param N the number of shares generated
      */
      ZFEC(size_t K, size_t n);

      size_t recovery_threshold() const { return m_K; }
      size_t generated_shares() const { return m_N; }

      std::string provider() const;

      /**
      * @param input the data to FEC
      * @param size the length in bytes of input
      * @param output_cb the output callback
      */
      void encode(
         const uint8_t input[], size_t size,
         std::function<void (size_t, size_t, const uint8_t[], size_t)> output_cb)
         const;

      /**
      * @param shares map of share id to share contents
      * @param share_size size in bytes of each share
      * @param output_cb the output callback
      */
      void decode(
         const std::map<size_t, const uint8_t*>& shares,
         size_t share_size,
         std::function<void (size_t, size_t, const uint8_t[], size_t)> output_cb)
         const;

   private:
      static void addmul(uint8_t z[], const uint8_t x[], uint8_t y, size_t size);

#if defined(BOTAN_HAS_ZFEC_SSE2)
      static size_t addmul_sse2(uint8_t z[], const uint8_t x[], uint8_t y, size_t size);
#endif

#if defined(BOTAN_HAS_ZFEC_VPERM)
      static size_t addmul_vperm(uint8_t z[], const uint8_t x[], uint8_t y, size_t size);
#endif

      const size_t m_K, m_N;
      std::vector<uint8_t> m_enc_matrix;
   };

}

#endif
