/**
* (C) 2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/argon2.h>
#include <botan/loadstor.h>
#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/rotate.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {

static const size_t SYNC_POINTS = 4;

secure_vector<uint8_t> argon2_H0(HashFunction& blake2b,
                                 size_t output_len,
                                 const char* password, size_t password_len,
                                 const uint8_t salt[], size_t salt_len,
                                 const uint8_t key[], size_t key_len,
                                 const uint8_t ad[], size_t ad_len,
                                 size_t y, size_t p, size_t M, size_t t)
   {
   const uint8_t v = 19; // Argon2 version code

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

   return blake2b.final();
   }

void Htick(secure_vector<uint8_t>& T,
           uint8_t output[],
           size_t output_len,
           HashFunction& blake2b,
           const secure_vector<uint8_t>& H0,
           size_t p0, size_t p1)
   {
   BOTAN_ASSERT_NOMSG(output_len % 64 == 0);

   blake2b.update_le(static_cast<uint32_t>(output_len));
   blake2b.update(H0);
   blake2b.update_le(static_cast<uint32_t>(p0));
   blake2b.update_le(static_cast<uint32_t>(p1));

   blake2b.final(&T[0]);

   while(output_len > 64)
      {
      copy_mem(output, &T[0], 32);
      output_len -= 32;
      output += 32;

      blake2b.update(T);
      blake2b.final(&T[0]);
      }

   if(output_len > 0)
      copy_mem(output, &T[0], output_len);
   }

void extract_key(uint8_t output[], size_t output_len,
                 const secure_vector<uint64_t>& B,
                 size_t memory, size_t threads)
   {
   const size_t lanes = memory / threads;

   secure_vector<uint64_t> sum(128);

   for(size_t lane = 0; lane != threads; ++lane)
      {
      size_t start = 128*(lane * lanes + lanes - 1);
      size_t end = 128*(lane * lanes + lanes);

      for(size_t j = start; j != end; ++j)
         {
         sum[j % 128] ^= B[j];
         }
      }

   secure_vector<uint8_t> sum8(1024);
   copy_out_le(sum8.data(), 1024, sum.data());

   if(output_len <= 64)
      {
      std::unique_ptr<HashFunction> blake2b = HashFunction::create_or_throw("BLAKE2b(" + std::to_string(output_len*8) + ")");
      blake2b->update_le(static_cast<uint32_t>(output_len));
      blake2b->update(sum8.data(), sum8.size());
      blake2b->final(output);
      }
   else
      {
      secure_vector<uint8_t> T(64);

      std::unique_ptr<HashFunction> blake2b = HashFunction::create_or_throw("BLAKE2b(512)");
      blake2b->update_le(static_cast<uint32_t>(output_len));
      blake2b->update(sum8.data(), sum8.size());
      blake2b->final(&T[0]);

      while(output_len > 64)
         {
         copy_mem(output, &T[0], 32);
         output_len -= 32;
         output += 32;

         if(output_len > 64)
            {
            blake2b->update(T);
            blake2b->final(&T[0]);
            }
         }

      if(output_len == 64)
         {
         blake2b->update(T);
         blake2b->final(output);
         }
      else
         {
         std::unique_ptr<HashFunction> blake2b_f = HashFunction::create_or_throw("BLAKE2b(" + std::to_string(output_len*8) + ")");
         blake2b_f->update(T);
         blake2b_f->final(output);
         }
      }
   }

void init_blocks(secure_vector<uint64_t>& B,
                 HashFunction& blake2b,
                 const secure_vector<uint8_t>& H0,
                 size_t memory,
                 size_t threads)
   {
   BOTAN_ASSERT_NOMSG(B.size() >= threads*256);

   secure_vector<uint8_t> H(1024);
   secure_vector<uint8_t> T(blake2b.output_length());

   for(size_t i = 0; i != threads; ++i)
      {
      const size_t B_off = i * (memory / threads);

      BOTAN_ASSERT_NOMSG(B.size() >= 128*(B_off+2));

      Htick(T, &H[0], H.size(), blake2b, H0, 0, i);

      for(size_t j = 0; j != 128; ++j)
         {
         B[128*B_off+j] = load_le<uint64_t>(H.data(), j);
         }

      Htick(T, &H[0], H.size(), blake2b, H0, 1, i);

      for(size_t j = 0; j != 128; ++j)
         {
         B[128*(B_off+1)+j] = load_le<uint64_t>(H.data(), j);
         }
      }
   }

inline void blamka_G(uint64_t& A, uint64_t& B, uint64_t& C, uint64_t& D)
   {
   A += B + (static_cast<uint64_t>(2) * static_cast<uint32_t>(A)) * static_cast<uint32_t>(B);
   D = rotr<32>(A ^ D);

   C += D + (static_cast<uint64_t>(2) * static_cast<uint32_t>(C)) * static_cast<uint32_t>(D);
   B = rotr<24>(B ^ C);

   A += B + (static_cast<uint64_t>(2) * static_cast<uint32_t>(A)) * static_cast<uint32_t>(B);
   D = rotr<16>(A ^ D);

   C += D + (static_cast<uint64_t>(2) * static_cast<uint32_t>(C)) * static_cast<uint32_t>(D);
   B = rotr<63>(B ^ C);
   }

inline void blamka(uint64_t& V0, uint64_t& V1, uint64_t& V2, uint64_t& V3,
                   uint64_t& V4, uint64_t& V5, uint64_t& V6, uint64_t& V7,
                   uint64_t& V8, uint64_t& V9, uint64_t& VA, uint64_t& VB,
                   uint64_t& VC, uint64_t& VD, uint64_t& VE, uint64_t& VF)
   {
   blamka_G(V0, V4, V8, VC);
   blamka_G(V1, V5, V9, VD);
   blamka_G(V2, V6, VA, VE);
   blamka_G(V3, V7, VB, VF);

   blamka_G(V0, V5, VA, VF);
   blamka_G(V1, V6, VB, VC);
   blamka_G(V2, V7, V8, VD);
   blamka_G(V3, V4, V9, VE);
   }

void process_block_xor(secure_vector<uint64_t>& T,
                       secure_vector<uint64_t>& B,
                       size_t offset,
                       size_t prev,
                       size_t new_offset)
   {
   for(size_t i = 0; i != 128; ++i)
      T[i] = B[128*prev+i] ^ B[128*new_offset+i];

   for(size_t i = 0; i != 128; i += 16)
      {
      blamka(T[i+ 0], T[i+ 1], T[i+ 2], T[i+ 3],
             T[i+ 4], T[i+ 5], T[i+ 6], T[i+ 7],
             T[i+ 8], T[i+ 9], T[i+10], T[i+11],
             T[i+12], T[i+13], T[i+14], T[i+15]);
      }

   for(size_t i = 0; i != 128 / 8; i += 2)
      {
      blamka(T[    i], T[    i+1], T[ 16+i], T[ 16+i+1],
             T[ 32+i], T[ 32+i+1], T[ 48+i], T[ 48+i+1],
             T[ 64+i], T[ 64+i+1], T[ 80+i], T[ 80+i+1],
             T[ 96+i], T[ 96+i+1], T[112+i], T[112+i+1]);
      }

   for(size_t i = 0; i != 128; ++i)
      B[128*offset + i] ^= T[i] ^ B[128*prev+i] ^ B[128*new_offset+i];
   }

void gen_2i_addresses(secure_vector<uint64_t>& T, secure_vector<uint64_t>& B,
                      size_t n, size_t lane, size_t slice, size_t memory,
                      size_t time, size_t mode, size_t cnt)
   {
   BOTAN_ASSERT_NOMSG(B.size() == 128);
   BOTAN_ASSERT_NOMSG(T.size() == 128);

   clear_mem(B.data(), B.size());
   B[0] = n;
   B[1] = lane;
   B[2] = slice;
   B[3] = memory;
   B[4] = time;
   B[5] = mode;
   B[6] = cnt;

   for(size_t r = 0; r != 2; ++r)
      {
      copy_mem(T.data(), B.data(), B.size());

      for(size_t i = 0; i != 128; i += 16)
         {
         blamka(T[i+ 0], T[i+ 1], T[i+ 2], T[i+ 3],
                T[i+ 4], T[i+ 5], T[i+ 6], T[i+ 7],
                T[i+ 8], T[i+ 9], T[i+10], T[i+11],
                T[i+12], T[i+13], T[i+14], T[i+15]);
         }
      for(size_t i = 0; i != 128 / 8; i += 2)
         {
         blamka(T[    i], T[    i+1], T[ 16+i], T[ 16+i+1],
                T[ 32+i], T[ 32+i+1], T[ 48+i], T[ 48+i+1],
                T[ 64+i], T[ 64+i+1], T[ 80+i], T[ 80+i+1],
                T[ 96+i], T[ 96+i+1], T[112+i], T[112+i+1]);
         }

      for(size_t i = 0; i != 128; ++i)
         B[i] ^= T[i];
      }
   }

uint32_t index_alpha(uint64_t random,
                     size_t lanes,
                     size_t segments,
                     size_t threads,
                     size_t n,
                     size_t slice,
                     size_t lane,
                     size_t index)
   {
   size_t ref_lane = static_cast<uint32_t>(random >> 32) % threads;

   if(n == 0 && slice == 0)
      ref_lane = lane;

   size_t m = 3*segments;
   size_t s = ((slice+1) % 4)*segments;

   if(lane == ref_lane)
      m += index;

   if(n == 0) {
         m = slice*segments;
         s = 0;
         if(slice == 0 || lane == ref_lane)
            m += index;
   }

   if(index == 0 || lane == ref_lane)
      m -= 1;

   uint64_t p = static_cast<uint32_t>(random);
   p = (p * p) >> 32;
   p = (p * m) >> 32;

   return static_cast<uint32_t>(ref_lane*lanes + (s + m - (p+1)) % lanes);
   }

void process_block_argon2d(secure_vector<uint64_t>& T,
                           secure_vector<uint64_t>& B,
                           size_t n, size_t slice, size_t lane,
                           size_t lanes, size_t segments, size_t threads)
   {
   size_t index = 0;
   if(n == 0 && slice == 0)
      index = 2;

   while(index < segments)
      {
      const size_t offset = lane*lanes + slice*segments + index;

      size_t prev = offset - 1;
      if(index == 0 && slice == 0)
         prev += lanes;

      const uint64_t random = B.at(128*prev);
      const size_t new_offset = index_alpha(random, lanes, segments, threads, n, slice, lane, index);

      process_block_xor(T, B, offset, prev, new_offset);

      index += 1;
      }
   }

void process_block_argon2i(secure_vector<uint64_t>& T,
                           secure_vector<uint64_t>& B,
                           size_t n, size_t slice, size_t lane,
                           size_t lanes, size_t segments, size_t threads, uint8_t mode,
                           size_t memory, size_t time)
   {
   size_t index = 0;
   if(n == 0 && slice == 0)
      index = 2;

   secure_vector<uint64_t> addresses(128);
   size_t address_counter = 1;

   gen_2i_addresses(T, addresses, n, lane, slice, memory, time, mode, address_counter);

   while(index < segments)
      {
      const size_t offset = lane*lanes + slice*segments + index;

      size_t prev = offset - 1;
      if(index == 0 && slice == 0)
         prev += lanes;

      if(index > 0 && index % 128 == 0)
         {
         address_counter += 1;
         gen_2i_addresses(T, addresses, n, lane, slice, memory, time, mode, address_counter);
         }

      const uint64_t random = addresses[index % 128];
      const size_t new_offset = index_alpha(random, lanes, segments, threads, n, slice, lane, index);

      process_block_xor(T, B, offset, prev, new_offset);

      index += 1;
      }
   }

void process_blocks(secure_vector<uint64_t>& B,
                    size_t t,
                    size_t memory,
                    size_t threads,
                    uint8_t mode)
   {
   const size_t lanes = memory / threads;
   const size_t segments = lanes / SYNC_POINTS;

   secure_vector<uint64_t> T(128);
   for(size_t n = 0; n != t; ++n)
      {
      for(size_t slice = 0; slice != SYNC_POINTS; ++slice)
         {
         // TODO can run this in Thread_Pool
         for(size_t lane = 0; lane != threads; ++lane)
            {
            if(mode == 1 || (mode == 2 && n == 0 && slice < SYNC_POINTS/2))
               process_block_argon2i(T, B, n, slice, lane, lanes, segments, threads, mode, memory, t);
            else
               process_block_argon2d(T, B, n, slice, lane, lanes, segments, threads);
            }
         }
      }

   }

}

void argon2(uint8_t output[], size_t output_len,
            const char* password, size_t password_len,
            const uint8_t salt[], size_t salt_len,
            const uint8_t key[], size_t key_len,
            const uint8_t ad[], size_t ad_len,
            uint8_t mode, size_t threads, size_t M, size_t t)
   {
   BOTAN_ARG_CHECK(mode == 0 || mode == 1 || mode == 2, "Unknown Argon2 mode parameter");
   BOTAN_ARG_CHECK(output_len >= 4, "Invalid Argon2 output length");
   BOTAN_ARG_CHECK(threads >= 1 && threads <= 128, "Invalid Argon2 threads parameter");
   BOTAN_ARG_CHECK(M >= 8*threads && M <= 8192*1024, "Invalid Argon2 M parameter");
   BOTAN_ARG_CHECK(t >= 1, "Invalid Argon2 t parameter");

   std::unique_ptr<HashFunction> blake2 = HashFunction::create_or_throw("BLAKE2b");

   const auto H0 = argon2_H0(*blake2, output_len,
                             password, password_len,
                             salt, salt_len,
                             key, key_len,
                             ad, ad_len,
                             mode, threads, M, t);

   const size_t memory = (M / (SYNC_POINTS*threads)) * (SYNC_POINTS*threads);

   secure_vector<uint64_t> B(memory * 1024/8);

   init_blocks(B, *blake2, H0, memory, threads);
   process_blocks(B, t, memory, threads, mode);

   clear_mem(output, output_len);
   extract_key(output, output_len, B, memory, threads);
   }

}
