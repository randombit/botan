/*
* GCM Mode Encryption
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/gcm.h>
#include <botan/internal/mode_utils.h>
#include <botan/internal/ct_utils.h>
#include <botan/ctr.h>

#if defined(BOTAN_HAS_GCM_CLMUL)
  #include <botan/internal/clmul.h>
  #include <botan/cpuid.h>
#endif

namespace Botan {

void GHASH::gcm_multiply(secure_vector<byte>& x) const
   {
#if defined(BOTAN_HAS_GCM_CLMUL)
   if(CPUID::has_clmul())
      return gcm_multiply_clmul(x.data(), m_H.data());
#endif

   static const u64bit R = 0xE100000000000000;

   u64bit H[2] = {
      load_be<u64bit>(m_H.data(), 0),
      load_be<u64bit>(m_H.data(), 1)
   };

   u64bit Z[2] = { 0, 0 };

   CT::poison(H, 2);
   CT::poison(Z, 2);
   CT::poison(x.data(), x.size());

   // SSE2 might be useful here

   for(size_t i = 0; i != 2; ++i)
      {
      const u64bit X = load_be<u64bit>(x.data(), i);

      u64bit mask = 0x8000000000000000;
      for(size_t j = 0; j != 64; ++j)
         {
         const u64bit XMASK = CT::expand_mask<u64bit>(X & mask);
         mask >>= 1;
         Z[0] ^= H[0] & XMASK;
         Z[1] ^= H[1] & XMASK;

         // GCM's bit ops are reversed so we carry out of the bottom
         const u64bit carry = R & CT::expand_mask<u64bit>(H[1] & 1);

         H[1] = (H[1] >> 1) | (H[0] << 63);
         H[0] = (H[0] >> 1) ^ carry;
         }
      }

   store_be<u64bit>(x.data(), Z[0], Z[1]);
   CT::unpoison(x.data(), x.size());
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

      xor_buf(ghash.data(), input, to_proc);

      gcm_multiply(ghash);

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
   store_be<u64bit>(final_block.data(), 8*ad_len, 8*text_len);
   ghash_update(hash, final_block.data(), final_block.size());
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
   if(cipher->block_size() != m_BS)
      throw Invalid_Argument("GCM requires a 128 bit cipher so cannot be used with " +
                                  cipher->name());

   m_ghash.reset(new GHASH);

   m_ctr.reset(new CTR_BE(cipher, 4)); // CTR_BE takes ownership of cipher

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
   return m_BS;
   }

Key_Length_Specification GCM_Mode::key_spec() const
   {
   return m_ctr->key_spec();
   }

void GCM_Mode::key_schedule(const byte key[], size_t keylen)
   {
   m_ctr->set_key(key, keylen);

   const std::vector<byte> zeros(m_BS);
   m_ctr->set_iv(zeros.data(), zeros.size());

   secure_vector<byte> H(m_BS);
   m_ctr->encipher(H);
   m_ghash->set_key(H);
   }

void GCM_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   m_ghash->set_associated_data(ad, ad_len);
   }

secure_vector<byte> GCM_Mode::start_raw(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   secure_vector<byte> y0(m_BS);

   if(nonce_len == 12)
      {
      copy_mem(y0.data(), nonce, nonce_len);
      y0[15] = 1;
      }
   else
      {
      y0 = m_ghash->nonce_hash(nonce, nonce_len);
      }

   m_ctr->set_iv(y0.data(), y0.size());

   secure_vector<byte> m_enc_y0(m_BS);
   m_ctr->encipher(m_enc_y0);

   m_ghash->start(m_enc_y0.data(), m_enc_y0.size());

   return secure_vector<byte>();
   }

void GCM_Encryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   m_ctr->cipher(buf, buf, sz);
   m_ghash->update(buf, sz);
   }

void GCM_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   update(buffer, offset);
   auto mac = m_ghash->final();
   buffer += std::make_pair(mac.data(), tag_size());
   }

void GCM_Decryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   m_ghash->update(buf, sz);
   m_ctr->cipher(buf, buf, sz);
   }

void GCM_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

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

   if(!same_mem(mac.data(), included_tag, tag_size()))
      throw Integrity_Failure("GCM tag check failed");

   buffer.resize(offset + remaining);
   }

}
