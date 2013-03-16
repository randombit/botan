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

#include <iostream>
#include <botan/hex.h>

namespace Botan {

void dump(const std::string& name, const byte x[], size_t x_len)
   {
   std::cout << name << " = " << hex_encode(x, x_len) << "\n";
   }

void dump(const std::string& name, const secure_vector<byte>& x)
   {
   dump(name, &x[0], x.size());
   }

bool rightshift(secure_vector<byte>& x)
   {
   byte carry = 0;

   for(size_t i = 0; i != x.size(); ++i)
      {
      byte carry2 = x[i] & 1;
      x[i] = (x[i] >> 1) | (carry << 7);
      carry = carry2;
      }

   return carry;
   }

bool get_bit(const secure_vector<byte>& x, size_t bit)
   {
   const byte b = x[16 - (bit / 8)];

   return (b >> (bit % 8)) & 0x01;
   }

secure_vector<byte>
gcm_multiply(const secure_vector<byte>& x,
             const secure_vector<byte>& y)
   {
   secure_vector<byte> z(x.size());
   secure_vector<byte> v = x;

   for(size_t i = 0; i != 128; ++i)
      {
      if(get_bit(y, i))
         z ^= v;

      const bool highbit = get_bit(v, 127);

      const bool carry = rightshift(v);
      BOTAN_ASSERT(carry == highbit, "That makes sense");

      if(highbit)
         v[0] ^= 0xE1;
      }

   return z;
   }

void ghash_update(const secure_vector<byte>& H,
                  secure_vector<byte>& ghash,
                  const byte input[], size_t length)
   {
   const size_t BS = 16;

   dump("H", H);

   dump("ghash-in", ghash);

   /*
   This assumes if less than block size input then we're just on the
   final block and should pad with zeros
   */
   while(length)
      {
      const size_t to_proc = std::min(length, BS);

      dump("input", input, to_proc);

      xor_buf(&ghash[0], &input[0], to_proc);

      ghash = gcm_multiply(ghash, H);

      dump("X", ghash);

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
   dump("lens", final_block);
   ghash_update(H, ghash, &final_block[0], final_block.size());
   dump("final ghash", ghash);
   }

/*
* GCM_Mode Constructor
*/
GCM_Mode::GCM_Mode(BlockCipher* cipher, size_t tag_size, bool decrypting) :
   Buffered_Filter(cipher->parallel_bytes(), decrypting ? tag_size : 0),
   m_tag_size(tag_size), m_cipher_name(cipher->name()),
   m_H(16), m_H_ad(16), m_H_current(16),
   m_ad_len(0), m_text_len(0),
   m_ctr_buf(8 * cipher->parallel_bytes())
   {
   m_ctr.reset(new CTR_BE(cipher)); // CTR_BE takes ownership of cipher

   if(m_tag_size < 8 || m_tag_size > 16)
      throw Invalid_Argument(name() + ": Bad tag size " + std::to_string(m_tag_size));
   }

/*
* Check if a keylength is valid for GCM
*/
bool GCM_Mode::valid_keylength(size_t n) const
   {
   if(!m_ctr->valid_keylength(n))
      return false;
   return true;
   }

void GCM_Mode::set_key(const SymmetricKey& key)
   {
   m_ctr->set_key(key);

   const std::vector<byte> zeros(16);
   m_ctr->set_iv(&zeros[0], zeros.size());

   zeroise(m_H);
   m_ctr->cipher(&m_H[0], &m_H[0], m_H.size());
   }

/*
* Set the GCM associated data
*/
void GCM_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   zeroise(m_H_ad);

   ghash_update(m_H, m_H_ad, ad, ad_len);
   m_ad_len = ad_len;
   }

/*
* Set the GCM nonce
*/
void GCM_Mode::set_nonce(const byte nonce[], size_t nonce_len)
   {
   secure_vector<byte> y0(16);

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

   m_y0_cipher.resize(16);
   m_ctr->cipher(&m_y0_cipher[0], &m_y0_cipher[0], m_y0_cipher.size());
   }

/*
* Do setup at the start of each message
*/
void GCM_Mode::start_msg()
   {
   m_text_len = 0;
   m_H_current = m_H_ad;
   }

/*
* Return the name of this cipher mode
*/
std::string GCM_Mode::name() const
   {
   return (m_cipher_name + "/GCM");
   }

void GCM_Mode::write(const byte input[], size_t length)
   {
   Buffered_Filter::write(input, length);
   }

void GCM_Mode::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void GCM_Encryption::buffered_block(const byte input[], size_t length)
   {
   while(length)
      {
      size_t copied = std::min<size_t>(length, m_ctr_buf.size());

      m_ctr->cipher(input, &m_ctr_buf[0], copied);
      ghash_update(m_H, m_H_current, &m_ctr_buf[0], copied);
      m_text_len += copied;

      send(m_ctr_buf, copied);

      input += copied;
      length -= copied;
      }
   }

void GCM_Encryption::buffered_final(const byte input[], size_t input_length)
   {
   buffered_block(input, input_length);

   ghash_finalize(m_H, m_H_current, m_ad_len, m_text_len);

   m_H_current ^= m_y0_cipher;

   send(m_H_current, m_tag_size);
   }

void GCM_Decryption::buffered_block(const byte input[], size_t length)
   {
   while(length)
      {
      size_t copied = std::min<size_t>(length, m_ctr_buf.size());

      ghash_update(m_H, m_H_current, &input[0], copied);
      m_ctr->cipher(input, &m_ctr_buf[0], copied);
      m_text_len += copied;

      send(m_ctr_buf, copied);

      input += copied;
      length -= copied;
      }
   }

void GCM_Decryption::buffered_final(const byte input[], size_t input_length)
   {
   BOTAN_ASSERT(input_length >= m_tag_size, "Have the tag as part of final input");

   const byte* included_tag = &input[input_length - m_tag_size];
   input_length -= m_tag_size;

   if(input_length) // handle any remaining input
      buffered_block(input, input_length);

   ghash_finalize(m_H, m_H_current, m_ad_len, m_text_len);

   m_H_current ^= m_y0_cipher;

   if(!same_mem(&m_H_current[0], included_tag, m_tag_size))
      throw Integrity_Failure("GCM tag check failed");
   }


}
