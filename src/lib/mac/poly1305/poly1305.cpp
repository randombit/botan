/*
* Derived from poly1305-donna-64.h by Andrew Moon <liquidsun@gmail.com>
* in https://github.com/floodyberry/poly1305-donna
*
* (C) 2014 Andrew Moon
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/poly1305.h>
#include <botan/loadstor.h>
#include <botan/mul128.h>
#include <botan/internal/donna128.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

namespace {

void poly1305_init(secure_vector<uint64_t>& X, const uint8_t key[32])
   {
   /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
   const uint64_t t0 = load_le<uint64_t>(key, 0);
   const uint64_t t1 = load_le<uint64_t>(key, 1);

   X[0] = ( t0                    ) & 0xffc0fffffff;
   X[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
   X[2] = ((t1 >> 24)             ) & 0x00ffffffc0f;

   /* h = 0 */
   X[3] = 0;
   X[4] = 0;
   X[5] = 0;

   /* save pad for later */
   X[6] = load_le<uint64_t>(key, 2);
   X[7] = load_le<uint64_t>(key, 3);
   }

void poly1305_blocks(secure_vector<uint64_t>& X, const uint8_t *m, size_t blocks, bool is_final = false)
   {
#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
   typedef donna128 uint128_t;
#endif

   const uint64_t hibit = is_final ? 0 : (static_cast<uint64_t>(1) << 40); /* 1 << 128 */

   const uint64_t r0 = X[0];
   const uint64_t r1 = X[1];
   const uint64_t r2 = X[2];

   const uint64_t M44 = 0xFFFFFFFFFFF;
   const uint64_t M42 = 0x3FFFFFFFFFF;

   uint64_t h0 = X[3+0];
   uint64_t h1 = X[3+1];
   uint64_t h2 = X[3+2];

   const uint64_t s1 = r1 * 20;
   const uint64_t s2 = r2 * 20;

   for(size_t i = 0; i != blocks; ++i)
      {
      const uint64_t t0 = load_le<uint64_t>(m, 0);
      const uint64_t t1 = load_le<uint64_t>(m, 1);

      h0 += (( t0                    ) & M44);
      h1 += (((t0 >> 44) | (t1 << 20)) & M44);
      h2 += (((t1 >> 24)             ) & M42) | hibit;

      const uint128_t d0 = uint128_t(h0) * r0 + uint128_t(h1) * s2 + uint128_t(h2) * s1;
      const uint64_t c0 = carry_shift(d0, 44);

      const uint128_t d1 = uint128_t(h0) * r1 + uint128_t(h1) * r0 + uint128_t(h2) * s2 + c0;
      const uint64_t c1 = carry_shift(d1, 44);

      const uint128_t d2 = uint128_t(h0) * r2 + uint128_t(h1) * r1 + uint128_t(h2) * r0 + c1;
      const uint64_t c2 = carry_shift(d2, 42);

      h0 = d0 & M44;
      h1 = d1 & M44;
      h2 = d2 & M42;

      h0 += c2 * 5;
      h1 += carry_shift(h0, 44);
      h0 = h0 & M44;

      m += 16;
      }

   X[3+0] = h0;
   X[3+1] = h1;
   X[3+2] = h2;
   }

void poly1305_finish(secure_vector<uint64_t>& X, uint8_t mac[16])
   {
   const uint64_t M44 = 0xFFFFFFFFFFF;
   const uint64_t M42 = 0x3FFFFFFFFFF;

   /* fully carry h */
   uint64_t h0 = X[3+0];
   uint64_t h1 = X[3+1];
   uint64_t h2 = X[3+2];

   uint64_t c;
                c = (h1 >> 44); h1 &= M44;
   h2 += c;     c = (h2 >> 42); h2 &= M42;
   h0 += c * 5; c = (h0 >> 44); h0 &= M44;
   h1 += c;     c = (h1 >> 44); h1 &= M44;
   h2 += c;     c = (h2 >> 42); h2 &= M42;
   h0 += c * 5; c = (h0 >> 44); h0 &= M44;
   h1 += c;

   /* compute h + -p */
   uint64_t g0 = h0 + 5; c = (g0 >> 44); g0 &= M44;
   uint64_t g1 = h1 + c; c = (g1 >> 44); g1 &= M44;
   uint64_t g2 = h2 + c - (static_cast<uint64_t>(1) << 42);

   /* select h if h < p, or h + -p if h >= p */
   const auto c_mask = CT::Mask<uint64_t>::expand(c);
   h0 = c_mask.select(g0, h0);
   h1 = c_mask.select(g1, h1);
   h2 = c_mask.select(g2, h2);

   /* h = (h + pad) */
   const uint64_t t0 = X[6];
   const uint64_t t1 = X[7];

   h0 += (( t0                    ) & M44)    ; c = (h0 >> 44); h0 &= M44;
   h1 += (((t0 >> 44) | (t1 << 20)) & M44) + c; c = (h1 >> 44); h1 &= M44;
   h2 += (((t1 >> 24)             ) & M42) + c;                 h2 &= M42;

   /* mac = h % (2^128) */
   h0 = ((h0      ) | (h1 << 44));
   h1 = ((h1 >> 20) | (h2 << 24));

   store_le(mac, h0, h1);

   /* zero out the state */
   clear_mem(X.data(), X.size());
   }

}

void Poly1305::clear()
   {
   zap(m_poly);
   zap(m_buf);
   m_buf_pos = 0;
   }

void Poly1305::key_schedule(const uint8_t key[], size_t)
   {
   m_buf_pos = 0;
   m_buf.resize(16);
   m_poly.resize(8);

   poly1305_init(m_poly, key);
   }

void Poly1305::add_data(const uint8_t input[], size_t length)
   {
   verify_key_set(m_poly.size() == 8);

   if(m_buf_pos)
      {
      buffer_insert(m_buf, m_buf_pos, input, length);

      if(m_buf_pos + length >= m_buf.size())
         {
         poly1305_blocks(m_poly, m_buf.data(), 1);
         input += (m_buf.size() - m_buf_pos);
         length -= (m_buf.size() - m_buf_pos);
         m_buf_pos = 0;
         }
      }

   const size_t full_blocks = length / m_buf.size();
   const size_t remaining   = length % m_buf.size();

   if(full_blocks)
      poly1305_blocks(m_poly, input, full_blocks);

   buffer_insert(m_buf, m_buf_pos, input + full_blocks * m_buf.size(), remaining);
   m_buf_pos += remaining;
   }

void Poly1305::final_result(uint8_t out[])
   {
   verify_key_set(m_poly.size() == 8);

   if(m_buf_pos != 0)
      {
      m_buf[m_buf_pos] = 1;
      const size_t len = m_buf.size() - m_buf_pos - 1;
      if (len > 0)
         {
         clear_mem(&m_buf[m_buf_pos+1], len);
         }
      poly1305_blocks(m_poly, m_buf.data(), 1, true);
      }

   poly1305_finish(m_poly, out);

   m_poly.clear();
   m_buf_pos = 0;
   }

}
