/*
* GCM Mode Encryption
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/gcm.h>
#include <botan/ctr.h>
#include <botan/internal/xor_buf.h>
#include <botan/loadstor.h>

#if defined(BOTAN_TARGET_SUPPORTS_CLMUL)
  #include <immintrin.h>
  #include <botan/cpuid.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_SUPPORTS_CLMUL)
__m128i gcm_multiply_clmul(__m128i a, __m128i b)
   {
   /*
   * Algorithms 1 and 5 from Intel's CLMUL guide
   */
   __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

   a = _mm_shuffle_epi8(a, BSWAP_MASK);
   b = _mm_shuffle_epi8(b, BSWAP_MASK);

   __m128i T0, T1, T2, T3, T4, T5;

   T0 = _mm_clmulepi64_si128(a, b, 0x00);
   T1 = _mm_clmulepi64_si128(a, b, 0x01);
   T2 = _mm_clmulepi64_si128(a, b, 0x10);
   T3 = _mm_clmulepi64_si128(a, b, 0x11);

   T1 = _mm_xor_si128(T1, T2);
   T2 = _mm_slli_si128(T1, 8);
   T1 = _mm_srli_si128(T1, 8);
   T0 = _mm_xor_si128(T0, T2);
   T3 = _mm_xor_si128(T3, T1);

   T4 = _mm_srli_epi32(T0, 31);
   T0 = _mm_slli_epi32(T0, 1);

   T5 = _mm_srli_epi32(T3, 31);
   T3 = _mm_slli_epi32(T3, 1);

   T2 = _mm_srli_si128(T4, 12);
   T5 = _mm_slli_si128(T5, 4);
   T4 = _mm_slli_si128(T4, 4);
   T0 = _mm_or_si128(T0, T4);
   T3 = _mm_or_si128(T3, T5);
   T3 = _mm_or_si128(T3, T2);

   T4 = _mm_slli_epi32(T0, 31);
   T5 = _mm_slli_epi32(T0, 30);
   T2 = _mm_slli_epi32(T0, 25);

   T4 = _mm_xor_si128(T4, T5);
   T4 = _mm_xor_si128(T4, T2);
   T5 = _mm_srli_si128(T4, 4);
   T3 = _mm_xor_si128(T3, T5);
   T4 = _mm_slli_si128(T4, 12);
   T0 = _mm_xor_si128(T0, T4);
   T3 = _mm_xor_si128(T3, T0);

   T4 = _mm_srli_epi32(T0, 1);
   T1 = _mm_srli_epi32(T0, 2);
   T2 = _mm_srli_epi32(T0, 7);
   T3 = _mm_xor_si128(T3, T1);
   T3 = _mm_xor_si128(T3, T2);
   T3 = _mm_xor_si128(T3, T4);

   return _mm_shuffle_epi8(T3, BSWAP_MASK);
   }
#endif

void gcm_multiply(secure_vector<byte>& x,
                  const secure_vector<byte>& h)
   {
#if defined(BOTAN_TARGET_SUPPORTS_CLMUL)
   if(CPUID::has_clmul())
      {
      __m128i xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&x[0]));
      __m128i hmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&h[0]));

      xmm = gcm_multiply_clmul(xmm, hmm);

      _mm_storeu_si128(reinterpret_cast<__m128i*>(&x[0]), xmm);
      return;
      }
#endif

   static const u64bit R = 0xE100000000000000;

   u64bit H[2] = {
      load_be<u64bit>(&h[0], 0),
      load_be<u64bit>(&h[0], 1)
   };

   u64bit Z[2] = { 0, 0 };

   // SSE2 might be useful here

   for(size_t i = 0; i != 2; ++i)
      {
      const u64bit X = load_be<u64bit>(&x[0], i);

      for(size_t j = 0; j != 64; ++j)
         {
         if((X >> (63-j)) & 1)
            {
            Z[0] ^= H[0];
            Z[1] ^= H[1];
            }

         const u64bit r = (H[1] & 1) ? R : 0;

         H[1] = (H[0] << 63) | (H[1] >> 1);
         H[0] = (H[0] >> 1) ^ r;
         }
      }

   store_be<u64bit>(&x[0], Z[0], Z[1]);
   }

}

void GHASH::ghash_update(secure_vector<byte>& ghash,
                         const byte input[], size_t length)
   {
   const size_t BS = 16;

   /*
   This assumes if less than block size input then we're just on the
   final block and should pad with zeros
   */
   while(length)
      {
      const size_t to_proc = std::min(length, BS);

      xor_buf(&ghash[0], &input[0], to_proc);

      gcm_multiply(ghash, m_H);

      input += to_proc;
      length -= to_proc;
      }
   }

void GHASH::key_schedule(const byte key[], size_t length)
   {
   m_H.assign(key, key+length);
   m_H_ad.resize(16);
   m_ad_len = 0;
   m_text_len = 0;
   }

void GHASH::start(const byte nonce[], size_t len)
   {
   m_nonce.assign(nonce, nonce + len);
   m_ghash = m_H_ad;
   }

void GHASH::set_associated_data(const byte input[], size_t length)
   {
   zeroise(m_H_ad);

   ghash_update(m_H_ad, input, length);
   m_ad_len = length;
   }

void GHASH::update(const byte input[], size_t length)
   {
   BOTAN_ASSERT(m_ghash.size() == 16, "Key was set");

   m_text_len += length;

   ghash_update(m_ghash, input, length);
   }

void GHASH::add_final_block(secure_vector<byte>& hash,
                            size_t ad_len, size_t text_len)
   {
   secure_vector<byte> final_block(16);
   store_be<u64bit>(&final_block[0], 8*ad_len, 8*text_len);
   ghash_update(hash, &final_block[0], final_block.size());
   }

secure_vector<byte> GHASH::final()
   {
   add_final_block(m_ghash, m_ad_len, m_text_len);

   secure_vector<byte> mac;
   mac.swap(m_ghash);

   mac ^= m_nonce;
   m_text_len = 0;
   return mac;
   }

secure_vector<byte> GHASH::nonce_hash(const byte nonce[], size_t nonce_len)
   {
   BOTAN_ASSERT(m_ghash.size() == 0, "nonce_hash called during wrong time");
   secure_vector<byte> y0(16);

   ghash_update(y0, nonce, nonce_len);
   add_final_block(y0, 0, nonce_len);

   return y0;
   }

void GHASH::clear()
   {
   zeroise(m_H);
   zeroise(m_H_ad);
   m_ghash.clear();
   m_text_len = m_ad_len = 0;
   }

/*
* GCM_Mode Constructor
*/
GCM_Mode::GCM_Mode(BlockCipher* cipher, size_t tag_size) :
   m_tag_size(tag_size),
   m_cipher_name(cipher->name())
   {
   if(cipher->block_size() != BS)
      throw std::invalid_argument("GCM requires a 128 bit cipher so cannot be used with " +
                                  cipher->name());

   m_ghash.reset(new GHASH);

   m_ctr.reset(new CTR_BE(cipher)); // CTR_BE takes ownership of cipher

   if(m_tag_size != 8 && m_tag_size != 16)
      throw Invalid_Argument(name() + ": Bad tag size " + std::to_string(m_tag_size));
   }

void GCM_Mode::clear()
   {
   m_ctr->clear();
   m_ghash->clear();
   }

std::string GCM_Mode::name() const
   {
   return (m_cipher_name + "/GCM");
   }

size_t GCM_Mode::update_granularity() const
   {
   return 4096; // CTR-BE's internal block size
   }

Key_Length_Specification GCM_Mode::key_spec() const
   {
   return m_ctr->key_spec();
   }

void GCM_Mode::key_schedule(const byte key[], size_t keylen)
   {
   m_ctr->set_key(key, keylen);

   const std::vector<byte> zeros(BS);
   m_ctr->set_iv(&zeros[0], zeros.size());

   secure_vector<byte> H(BS);
   m_ctr->encipher(H);
   m_ghash->set_key(H);
   }

void GCM_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   m_ghash->set_associated_data(ad, ad_len);
   }

secure_vector<byte> GCM_Mode::start(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   secure_vector<byte> y0(BS);

   if(nonce_len == 12)
      {
      copy_mem(&y0[0], nonce, nonce_len);
      y0[15] = 1;
      }
   else
      {
      y0 = m_ghash->nonce_hash(nonce, nonce_len);
      }

   m_ctr->set_iv(&y0[0], y0.size());

   secure_vector<byte> m_enc_y0(BS);
   m_ctr->encipher(m_enc_y0);

   m_ghash->start(&m_enc_y0[0], m_enc_y0.size());

   return secure_vector<byte>();
   }

void GCM_Encryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   m_ctr->cipher(buf, buf, sz);
   m_ghash->update(buf, sz);
   }

void GCM_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   update(buffer, offset);
   auto mac = m_ghash->final();
   buffer += std::make_pair(&mac[0], tag_size());
   }

void GCM_Decryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   m_ghash->update(buf, sz);
   m_ctr->cipher(buf, buf, sz);
   }

void GCM_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   BOTAN_ASSERT(sz >= tag_size(), "Have the tag as part of final input");

   const size_t remaining = sz - tag_size();

   // handle any final input before the tag
   if(remaining)
      {
      m_ghash->update(buf, remaining);
      m_ctr->cipher(buf, buf, remaining);
      }

   auto mac = m_ghash->final();

   const byte* included_tag = &buffer[remaining];

   if(!same_mem(&mac[0], included_tag, tag_size()))
      throw Integrity_Failure("GCM tag check failed");

   buffer.resize(offset + remaining);
   }

}
