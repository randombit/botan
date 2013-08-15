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

namespace Botan {

namespace {

void gcm_multiply(secure_vector<byte>& x,
                  const secure_vector<byte>& h)
   {
   static const u64bit R = 0xE100000000000000;

   u64bit H[2] = {
      load_be<u64bit>(&h[0], 0),
      load_be<u64bit>(&h[0], 1)
   };

   u64bit Z[2] = { 0, 0 };

   // Both CLMUL and SSE2 versions would be useful

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

void ghash_update(const secure_vector<byte>& H,
                  secure_vector<byte>& ghash,
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

      gcm_multiply(ghash, H);

      input += to_proc;
      length -= to_proc;
      }
   }

void ghash_finalize(const secure_vector<byte>& H,
                    secure_vector<byte>& ghash,
                    size_t ad_len, size_t text_len)
   {
   secure_vector<byte> final_block(16);
   store_be<u64bit>(&final_block[0], 8*ad_len, 8*text_len);
   ghash_update(H, ghash, &final_block[0], final_block.size());
   }

}

/*
* GCM_Mode Constructor
*/
GCM_Mode::GCM_Mode(BlockCipher* cipher, size_t tag_size) :
   m_tag_size(tag_size),
   m_cipher_name(cipher->name()),
   m_H(BS), m_H_ad(BS), m_mac(BS), m_enc_y0(BS),
   m_ad_len(0), m_text_len(0)
   {
   if(cipher->block_size() != BS)
      throw std::invalid_argument("GCM requires a 128 bit cipher so cannot be used with " +
                                  cipher->name());

   m_ctr.reset(new CTR_BE(cipher)); // CTR_BE takes ownership of cipher

   if(m_tag_size < 8 || m_tag_size > 16)
      throw Invalid_Argument(name() + ": Bad tag size " + to_string(m_tag_size));
   }

void GCM_Mode::clear()
   {
   zeroise(m_H);
   zeroise(m_H_ad);
   zeroise(m_mac);
   zeroise(m_enc_y0);
   m_ad_len = 0;
   m_text_len = 0;
   m_ctr.reset();
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

   zeroise(m_H);
   m_ctr->cipher(&m_H[0], &m_H[0], m_H.size());
   }

void GCM_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   zeroise(m_H_ad);

   ghash_update(m_H, m_H_ad, ad, ad_len);
   m_ad_len = ad_len;
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
      ghash_update(m_H, y0, nonce, nonce_len);
      ghash_finalize(m_H, y0, 0, nonce_len);
      }

   m_ctr->set_iv(&y0[0], y0.size());

   zeroise(m_enc_y0);
   m_ctr->encipher(m_enc_y0);

   m_text_len = 0;
   m_mac = m_H_ad;

   return secure_vector<byte>();
   }

void GCM_Encryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   m_ctr->cipher(buf, buf, sz);
   ghash_update(m_H, m_mac, buf, sz);
   m_text_len += sz;
   }

void GCM_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   update(buffer, offset);

   ghash_finalize(m_H, m_mac, m_ad_len, m_text_len);

   m_mac ^= m_enc_y0;

   buffer += std::make_pair(&m_mac[0], tag_size());
   }

void GCM_Decryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   ghash_update(m_H, m_mac, buf, sz);
   m_ctr->cipher(buf, buf, sz);
   m_text_len += sz;
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
      ghash_update(m_H, m_mac, buf, remaining);
      m_ctr->cipher(buf, buf, remaining);
      m_text_len += remaining;
      }

   ghash_finalize(m_H, m_mac, m_ad_len, m_text_len);

   m_mac ^= m_enc_y0;

   const byte* included_tag = &buffer[remaining];

   if(!same_mem(&m_mac[0], included_tag, tag_size()))
      throw Integrity_Failure("GCM tag check failed");

   buffer.resize(offset + remaining);
   }

}
