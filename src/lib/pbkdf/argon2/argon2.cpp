/**
* (C) 2018,2019,2022 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/argon2.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <limits>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif

#if defined(BOTAN_HAS_ARGON2_AVX2) || defined(BOTAN_HAS_ARGON2_SSSE3)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

const size_t SYNC_POINTS = 4;

void argon2_H0(uint8_t H0[64],
               HashFunction& blake2b,
               size_t output_len,
               const char* password,
               size_t password_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t key[],
               size_t key_len,
               const uint8_t ad[],
               size_t ad_len,
               size_t y,
               size_t p,
               size_t M,
               size_t t) {
   const uint8_t v = 19;  // Argon2 version code

   blake2b.update_le(static_cast<uint32_t>(p));
   blake2b.update_le(static_cast<uint32_t>(output_len));
   blake2b.update_le(static_cast<uint32_t>(M));
   blake2b.update_le(static_cast<uint32_t>(t));
   blake2b.update_le(static_cast<uint32_t>(v));
   blake2b.update_le(static_cast<uint32_t>(y));

   blake2b.update_le(static_cast<uint32_t>(password_len));
   blake2b.update(cast_char_ptr_to_uint8(password), password_len);

   blake2b.update_le(static_cast<uint32_t>(salt_len));
   blake2b.update(salt, salt_len);

   blake2b.update_le(static_cast<uint32_t>(key_len));
   blake2b.update(key, key_len);

   blake2b.update_le(static_cast<uint32_t>(ad_len));
   blake2b.update(ad, ad_len);

   blake2b.final(H0);
}

void extract_key(uint8_t output[], size_t output_len, const secure_vector<uint64_t>& B, size_t memory, size_t threads) {
   const size_t lanes = memory / threads;

   uint64_t sum[128] = {0};

   for(size_t lane = 0; lane != threads; ++lane) {
      const size_t start = 128 * (lane * lanes + lanes - 1);
      const size_t end = 128 * (lane * lanes + lanes);

      for(size_t j = start; j != end; ++j) {
         sum[j % 128] ^= B[j];
      }
   }

   if(output_len <= 64) {
      auto blake2b = HashFunction::create_or_throw(fmt("BLAKE2b({})", output_len * 8));
      blake2b->update_le(static_cast<uint32_t>(output_len));
      for(size_t i = 0; i != 128; ++i) {
         blake2b->update_le(sum[i]);
      }
      blake2b->final(output);
   } else {
      secure_vector<uint8_t> T(64);

      auto blake2b = HashFunction::create_or_throw("BLAKE2b(512)");
      blake2b->update_le(static_cast<uint32_t>(output_len));
      for(size_t i = 0; i != 128; ++i) {
         blake2b->update_le(sum[i]);
      }
      blake2b->final(&T[0]);

      while(output_len > 64) {
         copy_mem(output, &T[0], 32);
         output_len -= 32;
         output += 32;

         if(output_len > 64) {
            blake2b->update(T);
            blake2b->final(&T[0]);
         }
      }

      if(output_len == 64) {
         blake2b->update(T);
         blake2b->final(output);
      } else {
         auto blake2b_f = HashFunction::create_or_throw(fmt("BLAKE2b({})", output_len * 8));
         blake2b_f->update(T);
         blake2b_f->final(output);
      }
   }
}

void init_blocks(
   secure_vector<uint64_t>& B, HashFunction& blake2b, const uint8_t H0[64], size_t memory, size_t threads) {
   BOTAN_ASSERT_NOMSG(B.size() >= threads * 256);

   for(size_t i = 0; i != threads; ++i) {
      const size_t B_off = i * (memory / threads);

      BOTAN_ASSERT_NOMSG(B.size() >= 128 * (B_off + 2));

      for(size_t j = 0; j != 2; ++j) {
         uint8_t T[64] = {0};

         blake2b.update_le(static_cast<uint32_t>(1024));
         blake2b.update(H0, 64);
         blake2b.update_le(static_cast<uint32_t>(j));
         blake2b.update_le(static_cast<uint32_t>(i));
         blake2b.final(T);

         for(size_t k = 0; k != 30; ++k) {
            load_le(&B[128 * (B_off + j) + 4 * k], T, 32 / 8);
            blake2b.update(T, 64);
            blake2b.final(T);
         }

         load_le(&B[128 * (B_off + j) + 4 * 30], T, 64 / 8);
      }
   }
}

BOTAN_FORCE_INLINE void blamka_G(uint64_t& A, uint64_t& B, uint64_t& C, uint64_t& D) {
   A += B + (static_cast<uint64_t>(2) * static_cast<uint32_t>(A)) * static_cast<uint32_t>(B);
   D = rotr<32>(A ^ D);

   C += D + (static_cast<uint64_t>(2) * static_cast<uint32_t>(C)) * static_cast<uint32_t>(D);
   B = rotr<24>(B ^ C);

   A += B + (static_cast<uint64_t>(2) * static_cast<uint32_t>(A)) * static_cast<uint32_t>(B);
   D = rotr<16>(A ^ D);

   C += D + (static_cast<uint64_t>(2) * static_cast<uint32_t>(C)) * static_cast<uint32_t>(D);
   B = rotr<63>(B ^ C);
}

}  // namespace

void Argon2::blamka(uint64_t N[128], uint64_t T[128]) {
#if defined(BOTAN_HAS_ARGON2_AVX2)
   if(CPUID::has_avx2()) {
      return Argon2::blamka_avx2(N, T);
   }
#endif

#if defined(BOTAN_HAS_ARGON2_SSSE3)
   if(CPUID::has_ssse3()) {
      return Argon2::blamka_ssse3(N, T);
   }
#endif

   copy_mem(T, N, 128);

   for(size_t i = 0; i != 128; i += 16) {
      blamka_G(T[i + 0], T[i + 4], T[i + 8], T[i + 12]);
      blamka_G(T[i + 1], T[i + 5], T[i + 9], T[i + 13]);
      blamka_G(T[i + 2], T[i + 6], T[i + 10], T[i + 14]);
      blamka_G(T[i + 3], T[i + 7], T[i + 11], T[i + 15]);

      blamka_G(T[i + 0], T[i + 5], T[i + 10], T[i + 15]);
      blamka_G(T[i + 1], T[i + 6], T[i + 11], T[i + 12]);
      blamka_G(T[i + 2], T[i + 7], T[i + 8], T[i + 13]);
      blamka_G(T[i + 3], T[i + 4], T[i + 9], T[i + 14]);
   }

   for(size_t i = 0; i != 128 / 8; i += 2) {
      blamka_G(T[i + 0], T[i + 32], T[i + 64], T[i + 96]);
      blamka_G(T[i + 1], T[i + 33], T[i + 65], T[i + 97]);
      blamka_G(T[i + 16], T[i + 48], T[i + 80], T[i + 112]);
      blamka_G(T[i + 17], T[i + 49], T[i + 81], T[i + 113]);

      blamka_G(T[i + 0], T[i + 33], T[i + 80], T[i + 113]);
      blamka_G(T[i + 1], T[i + 48], T[i + 81], T[i + 96]);
      blamka_G(T[i + 16], T[i + 49], T[i + 64], T[i + 97]);
      blamka_G(T[i + 17], T[i + 32], T[i + 65], T[i + 112]);
   }

   for(size_t i = 0; i != 128; ++i) {
      N[i] ^= T[i];
   }
}

namespace {

void gen_2i_addresses(uint64_t T[128],
                      uint64_t B[128],
                      size_t n,
                      size_t lane,
                      size_t slice,
                      size_t memory,
                      size_t time,
                      size_t mode,
                      size_t cnt) {
   clear_mem(B, 128);

   B[0] = n;
   B[1] = lane;
   B[2] = slice;
   B[3] = memory;
   B[4] = time;
   B[5] = mode;
   B[6] = cnt;

   for(size_t r = 0; r != 2; ++r) {
      Argon2::blamka(B, T);
   }
}

uint32_t index_alpha(
   uint64_t random, size_t lanes, size_t segments, size_t threads, size_t n, size_t slice, size_t lane, size_t index) {
   size_t ref_lane = static_cast<uint32_t>(random >> 32) % threads;

   if(n == 0 && slice == 0) {
      ref_lane = lane;
   }

   size_t m = 3 * segments;
   size_t s = ((slice + 1) % 4) * segments;

   if(lane == ref_lane) {
      m += index;
   }

   if(n == 0) {
      m = slice * segments;
      s = 0;
      if(slice == 0 || lane == ref_lane) {
         m += index;
      }
   }

   if(index == 0 || lane == ref_lane) {
      m -= 1;
   }

   uint64_t p = static_cast<uint32_t>(random);
   p = (p * p) >> 32;
   p = (p * m) >> 32;

   return static_cast<uint32_t>(ref_lane * lanes + (s + m - (p + 1)) % lanes);
}

void process_block(secure_vector<uint64_t>& B,
                   size_t n,
                   size_t slice,
                   size_t lane,
                   size_t lanes,
                   size_t segments,
                   size_t threads,
                   uint8_t mode,
                   size_t memory,
                   size_t time) {
   uint64_t T[128];
   size_t index = 0;
   if(n == 0 && slice == 0) {
      index = 2;
   }

   const bool use_2i = mode == 1 || (mode == 2 && n == 0 && slice < SYNC_POINTS / 2);

   uint64_t addresses[128];
   size_t address_counter = 1;

   if(use_2i) {
      gen_2i_addresses(T, addresses, n, lane, slice, memory, time, mode, address_counter);
   }

   while(index < segments) {
      const size_t offset = lane * lanes + slice * segments + index;

      size_t prev = offset - 1;
      if(index == 0 && slice == 0) {
         prev += lanes;
      }

      if(use_2i && index > 0 && index % 128 == 0) {
         address_counter += 1;
         gen_2i_addresses(T, addresses, n, lane, slice, memory, time, mode, address_counter);
      }

      const uint64_t random = use_2i ? addresses[index % 128] : B.at(128 * prev);
      const size_t new_offset = index_alpha(random, lanes, segments, threads, n, slice, lane, index);

      uint64_t N[128];
      for(size_t i = 0; i != 128; ++i) {
         N[i] = B[128 * prev + i] ^ B[128 * new_offset + i];
      }

      Argon2::blamka(N, T);

      for(size_t i = 0; i != 128; ++i) {
         B[128 * offset + i] ^= N[i];
      }

      index += 1;
   }
}

void process_blocks(secure_vector<uint64_t>& B, size_t t, size_t memory, size_t threads, uint8_t mode) {
   const size_t lanes = memory / threads;
   const size_t segments = lanes / SYNC_POINTS;

#if defined(BOTAN_HAS_THREAD_UTILS)
   if(threads > 1) {
      auto& thread_pool = Thread_Pool::global_instance();

      for(size_t n = 0; n != t; ++n) {
         for(size_t slice = 0; slice != SYNC_POINTS; ++slice) {
            std::vector<std::future<void>> fut_results;
            fut_results.reserve(threads);

            for(size_t lane = 0; lane != threads; ++lane) {
               fut_results.push_back(thread_pool.run(
                  process_block, std::ref(B), n, slice, lane, lanes, segments, threads, mode, memory, t));
            }

            for(auto& fut : fut_results) {
               fut.get();
            }
         }
      }

      return;
   }
#endif

   for(size_t n = 0; n != t; ++n) {
      for(size_t slice = 0; slice != SYNC_POINTS; ++slice) {
         for(size_t lane = 0; lane != threads; ++lane) {
            process_block(B, n, slice, lane, lanes, segments, threads, mode, memory, t);
         }
      }
   }
}

}  // namespace

void Argon2::argon2(uint8_t output[],
                    size_t output_len,
                    const char* password,
                    size_t password_len,
                    const uint8_t salt[],
                    size_t salt_len,
                    const uint8_t key[],
                    size_t key_len,
                    const uint8_t ad[],
                    size_t ad_len) const {
   BOTAN_ARG_CHECK(output_len >= 4 && output_len <= std::numeric_limits<uint32_t>::max(),
                   "Invalid Argon2 output length");
   BOTAN_ARG_CHECK(password_len <= std::numeric_limits<uint32_t>::max(), "Invalid Argon2 password length");
   BOTAN_ARG_CHECK(salt_len <= std::numeric_limits<uint32_t>::max(), "Invalid Argon2 salt length");
   BOTAN_ARG_CHECK(key_len <= std::numeric_limits<uint32_t>::max(), "Invalid Argon2 key length");
   BOTAN_ARG_CHECK(ad_len <= std::numeric_limits<uint32_t>::max(), "Invalid Argon2 ad length");

   auto blake2 = HashFunction::create_or_throw("BLAKE2b");

   uint8_t H0[64] = {0};
   argon2_H0(H0,
             *blake2,
             output_len,
             password,
             password_len,
             salt,
             salt_len,
             key,
             key_len,
             ad,
             ad_len,
             m_family,
             m_p,
             m_M,
             m_t);

   const size_t memory = (m_M / (SYNC_POINTS * m_p)) * (SYNC_POINTS * m_p);

   secure_vector<uint64_t> B(memory * 1024 / 8);

   init_blocks(B, *blake2, H0, memory, m_p);
   process_blocks(B, m_t, memory, m_p, m_family);

   clear_mem(output, output_len);
   extract_key(output, output_len, B, memory, m_p);
}

}  // namespace Botan
