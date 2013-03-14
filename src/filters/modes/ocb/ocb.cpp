/*
* OCB Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ocb.h>
#include <botan/cmac.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

#include <iostream>

namespace Botan {

namespace ShouldNotBeHere {

inline void xor_mem(byte out[], const byte in[], size_t length)
   {
   for(size_t i = 0; i != length; ++i)
      out[i] ^= in[i];
   }

inline void xor_mem(byte out[], const byte in[], const byte in2[], size_t length)
   {
   for(size_t i = 0; i != length; ++i)
      out[i] = in[i] ^ in2[i];
   }


template<typename T, typename Alloc, typename Alloc2>
std::vector<T, Alloc>&
operator^=(std::vector<T, Alloc>& out,
           const std::vector<T, Alloc2>& in)
   {
   if(out.size() < in.size())
      out.resize(in.size());

   xor_mem(&out[0], &in[0], in.size());
   return out;
   }


}

using namespace ShouldNotBeHere;


// Has to be in Botan namespace so unique_ptr can reference it
class L_computer
   {
   public:
      L_computer(const BlockCipher& cipher);

      const secure_vector<byte>& star() const { return m_L_star; }

      const secure_vector<byte>& dollar() const { return m_L_dollar; }

      // this should apply ctz (and cache it)
      const secure_vector<byte>& operator()(size_t i) const;
   private:
      secure_vector<byte> poly_double(const secure_vector<byte>& in) const
         {
         return CMAC::poly_double(in, 0x87);
         }

      secure_vector<byte> m_L_dollar, m_L_star;
      mutable std::vector<secure_vector<byte>> m_L;
   };

L_computer::L_computer(const BlockCipher& cipher)
   {
   m_L_star.resize(16);
   cipher.encrypt(m_L_star);
   m_L_dollar = poly_double(star());
   m_L.push_back(poly_double(dollar()));
   }

const secure_vector<byte>& L_computer::operator()(size_t i) const
   {
   while(m_L.size() <= i)
      m_L.push_back(poly_double(m_L.back()));

   return m_L.at(i);
   }

namespace {

/*
* OCB's HASH
*/
secure_vector<byte> ocb_hash(const L_computer& L,
                             const BlockCipher& cipher,
                             const byte ad[], size_t ad_len)
   {
   secure_vector<byte> sum(16);
   secure_vector<byte> offset(16);

   secure_vector<byte> buf(16);

   const size_t ad_blocks = (ad_len / 16);
   const size_t ad_remainder = (ad_len % 16);

   for(size_t i = 0; i != ad_blocks; ++i)
      {
      // this loop could run in parallel
      offset ^= L(ctz(i+1));

      buf = offset;
      xor_mem(&buf[0], &ad[16*i], 16);

      cipher.encrypt(buf);

      sum ^= buf;
      }

   if(ad_remainder)
      {
      offset ^= L.star();

      buf = offset;
      xor_mem(&buf[0], &ad[16*ad_blocks], ad_remainder);
      buf[ad_len % 16] ^= 0x80;

      cipher.encrypt(buf);

      sum ^= buf;
      }

   return sum;
   }

}

OCB_Mode::OCB_Mode(BlockCipher* cipher, size_t tag_size) :
   Buffered_Filter(16, 0),
   m_cipher(cipher), m_tag_size(tag_size),
   m_ad_hash(16), m_offset(16), m_checksum(16)
   {
   if(m_cipher->block_size() != 16)
      throw std::invalid_argument("OCB requires a 128 bit cipher so cannot be used with " +
                                  m_cipher->name());
   }

OCB_Mode::~OCB_Mode() { /* for unique_ptr destructor */ }

bool OCB_Mode::valid_keylength(size_t n) const
   {
   return m_cipher->valid_keylength(n);
   }

std::string OCB_Mode::name() const
   {
   return m_cipher->name() + "/OCB"; // include tag size
   }

void OCB_Mode::set_key(const SymmetricKey& key)
   {
   m_cipher->set_key(key);
   m_L.reset(new L_computer(*m_cipher));
   }

void OCB_Mode::set_nonce(const byte nonce[], size_t nonce_len)
   {
   if(nonce_len > 15) // OCB supports 127 bits, we support 120
      throw Invalid_IV_Length(name(), nonce_len);

   byte bottom;
   secure_vector<byte> stretch;

   if(1) // need to recompute stretch (save iv to compare)
      {
      secure_vector<byte> buf(16);

      const size_t offset = 16 - nonce_len;

      copy_mem(&buf[offset], nonce, nonce_len);
      buf[offset-1] = 1;

      bottom = buf[15] & 0x3F;
      buf[15] &= 0xC0;

      m_cipher->encrypt(buf);

      for(size_t i = 0; i != 8; ++i)
         buf.push_back(buf[i] ^ buf[i+1]);

      stretch = buf;
      }

   // now set the offset from stretch and bottom

   const size_t shift_bytes = bottom / 8;
   const size_t shift_bits  = bottom % 8;

   for(size_t i = 0; i != 16; ++i)
      {
      m_offset[i]  = (stretch[i+shift_bytes] << shift_bits);
      m_offset[i] |= (stretch[i+shift_bytes+1] >> (8-shift_bits));
      }
   }

void OCB_Mode::start_msg()
   {
   //BOTAN_ASSERT(m_nonce_state.fresh_nonce(), "Nonce state is fresh");
   }

void OCB_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   m_ad_hash = ocb_hash(*m_L, *m_cipher, &ad[0], ad_len);
   }

void OCB_Mode::write(const byte input[], size_t length)
   {
   Buffered_Filter::write(input, length);
   }

void OCB_Mode::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void OCB_Encryption::buffered_block(const byte input[], size_t input_length)
   {
   BOTAN_ASSERT(input_length % 16 == 0, "Input length is an even number of blocks");

   const size_t blocks = input_length / 16;

   const L_computer& L = *m_L;

   secure_vector<byte> ctext_buf(16);

   for(size_t i = 0; i != blocks; ++i)
      {
      // could run in parallel

      xor_mem(&m_checksum[0], &input[16*i], 16);

      m_offset ^= L(ctz(++m_block_index));

      ctext_buf = m_offset;
      xor_mem(&ctext_buf[0], &input[16*i], 16);
      m_cipher->encrypt(ctext_buf);
      ctext_buf ^= m_offset;

      send(ctext_buf);
      }
   }

void OCB_Encryption::buffered_final(const byte input[], size_t input_length)
   {
   /*
   todo - might have multiple blocks here if buffering up multiple
   blocks for bitslice mode, run those first by calling buffered_write
   directly
   */

   if(input_length)
      {
      BOTAN_ASSERT(input_length < 16, "Only a partial block left");

      xor_mem(&m_checksum[0], &input[0], input_length);
      m_checksum[input_length] ^= 0x80;

      m_offset ^= m_L->star(); // Offset_*

      secure_vector<byte> buf(16);
      m_cipher->encrypt(m_offset, buf);
      xor_mem(&buf[0], &input[0], input_length);

      send(buf, input_length); // final ciphertext
      }

   // now compute the tag
   secure_vector<byte> mac = m_offset;
   mac ^= m_checksum;
   mac ^= m_L->dollar();

   m_cipher->encrypt(mac);

   mac ^= m_ad_hash;

   send(mac);

   zeroise(m_checksum);
   zeroise(m_offset);
   }

}
