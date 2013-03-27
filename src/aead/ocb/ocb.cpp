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

namespace Botan {

// Has to be in Botan namespace so unique_ptr can reference it
class L_computer
   {
   public:
      L_computer(const BlockCipher& cipher)
         {
         m_L_star.resize(cipher.block_size());
         cipher.encrypt(m_L_star);
         m_L_dollar = poly_double(star());
         m_L.push_back(poly_double(dollar()));
         }

      const secure_vector<byte>& star() const { return m_L_star; }

      const secure_vector<byte>& dollar() const { return m_L_dollar; }

      const secure_vector<byte>& operator()(size_t i) const { return get(i); }

      const secure_vector<byte>& get(size_t i) const
         {
         while(m_L.size() <= i)
            m_L.push_back(poly_double(m_L.back()));

         return m_L.at(i);
         }

   private:
      secure_vector<byte> poly_double(const secure_vector<byte>& in) const
         {
         return CMAC::poly_double(in, 0x87);
         }

      secure_vector<byte> m_L_dollar, m_L_star;
      mutable std::vector<secure_vector<byte>> m_L;
   };

class Nonce_State
   {
   public:
      Nonce_State(const BlockCipher& cipher) : m_cipher(cipher) {}

      secure_vector<byte> update_nonce(const byte nonce[],
                                       size_t nonce_len);
   private:
      const BlockCipher& m_cipher;
      secure_vector<byte> m_last_nonce;
      secure_vector<byte> m_stretch;
   };

secure_vector<byte>
Nonce_State::update_nonce(const byte nonce[], size_t nonce_len)
   {
   const size_t BS = 16;

   BOTAN_ASSERT(nonce_len < BS, "Nonce is less than 128 bits");

   secure_vector<byte> nonce_buf(BS);

   copy_mem(&nonce_buf[BS - nonce_len], nonce, nonce_len);
   nonce_buf[BS - nonce_len - 1] = 1;

   const byte bottom = nonce_buf[15] & 0x3F;
   nonce_buf[15] &= 0xC0;

   const bool need_new_stretch = (m_last_nonce != nonce_buf);

   if(need_new_stretch)
      {
      m_last_nonce = nonce_buf;

      m_cipher.encrypt(nonce_buf);

      for(size_t i = 0; i != 8; ++i)
         nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i+1]);

      m_stretch = nonce_buf;
      }

   // now set the offset from stretch and bottom

   const size_t shift_bytes = bottom / 8;
   const size_t shift_bits  = bottom % 8;

   secure_vector<byte> offset(BS);
   for(size_t i = 0; i != BS; ++i)
      {
      offset[i]  = (m_stretch[i+shift_bytes] << shift_bits);
      offset[i] |= (m_stretch[i+shift_bytes+1] >> (8-shift_bits));
      }

   return offset;
   }

namespace {

/*
* OCB's HASH
*/
secure_vector<byte> ocb_hash(const L_computer& L,
                             const BlockCipher& cipher,
                             const byte ad[], size_t ad_len)
   {
   const size_t BS = cipher.block_size();

   secure_vector<byte> sum(BS);
   secure_vector<byte> offset(BS);

   secure_vector<byte> buf(BS);

   const size_t ad_blocks = (ad_len / BS);
   const size_t ad_remainder = (ad_len % BS);

   for(size_t i = 0; i != ad_blocks; ++i)
      {
      // this loop could run in parallel
      offset ^= L(ctz(i+1));

      buf = offset;
      xor_buf(&buf[0], &ad[BS*i], BS);

      cipher.encrypt(buf);

      sum ^= buf;
      }

   if(ad_remainder)
      {
      offset ^= L.star();

      buf = offset;
      xor_buf(&buf[0], &ad[BS*ad_blocks], ad_remainder);
      buf[ad_len % BS] ^= 0x80;

      cipher.encrypt(buf);

      sum ^= buf;
      }

   return sum;
   }

}

OCB_Mode::OCB_Mode(BlockCipher* cipher, size_t tag_size) :
   m_cipher(cipher),
   m_tag_size(tag_size),
   m_ad_hash(BS), m_offset(BS), m_checksum(BS)
   {
   if(m_cipher->block_size() != BS)
      throw std::invalid_argument("OCB requires a 128 bit cipher so cannot be used with " +
                                  m_cipher->name());

   if(m_tag_size != 16) // fixme: 64, 96 bits also supported
      throw std::invalid_argument("OCB cannot produce a " + std::to_string(m_tag_size) +
                                  " byte tag");

   }

OCB_Mode::~OCB_Mode() { /* for unique_ptr destructor */ }

void OCB_Mode::clear()
   {
   m_cipher.reset();
   m_L.reset();
   zeroise(m_ad_hash);
   zeroise(m_offset);
   zeroise(m_checksum);
   }

bool OCB_Mode::valid_nonce_length(size_t length) const
   {
   return (length > 0 && length < 16);
   }

std::string OCB_Mode::name() const
   {
   return m_cipher->name() + "/OCB"; // include tag size
   }

size_t OCB_Mode::update_granularity() const
   {
   return 8 * m_cipher->parallel_bytes();
   }

Key_Length_Specification OCB_Mode::key_spec() const
   {
   return m_cipher->key_spec();
   }

void OCB_Mode::key_schedule(const byte key[], size_t length)
   {
   m_cipher->set_key(key, length);
   m_L.reset(new L_computer(*m_cipher));
   m_nonce_state.reset(new Nonce_State(*m_cipher));
   }

void OCB_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   BOTAN_ASSERT(m_L, "A key was set");
   m_ad_hash = ocb_hash(*m_L, *m_cipher, &ad[0], ad_len);
   }

secure_vector<byte> OCB_Mode::start(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   BOTAN_ASSERT(m_nonce_state, "A key was set");

   m_offset = m_nonce_state->update_nonce(nonce, nonce_len);
   zeroise(m_checksum);
   m_block_index = 0;

   return secure_vector<byte>();
   }

void OCB_Encryption::encrypt(byte buffer[], size_t blocks)
   {
   const L_computer& L = *m_L; // convenient name

   const size_t par_bytes = m_cipher->parallel_bytes();

   BOTAN_ASSERT(par_bytes % BS == 0, "Cipher is parallel in full blocks");

   const size_t par_blocks = par_bytes / BS;

   secure_vector<byte> csum_accum(par_bytes);
   secure_vector<byte> offsets(par_bytes);

   size_t blocks_left = blocks;

   while(blocks_left)
      {
      const size_t proc_blocks = std::min(blocks_left, par_blocks);
      const size_t proc_bytes = proc_blocks * BS;

      for(size_t i = 0; i != proc_blocks; ++i)
         { // could be done in parallel
         m_offset ^= L(ctz(++m_block_index));
         copy_mem(&offsets[BS*i], &m_offset[0], BS);
         }

      xor_buf(&csum_accum[0], &buffer[0], proc_bytes);

      xor_buf(&buffer[0], &offsets[0], proc_bytes);

      m_cipher->encrypt_n(&buffer[0], &buffer[0], proc_blocks);

      xor_buf(&buffer[0], &offsets[0], proc_bytes);

      buffer += proc_bytes;
      blocks_left -= proc_blocks;
      }

   // fold into checksum
   for(size_t i = 0; i != csum_accum.size(); ++i)
      m_checksum[i % BS] ^= csum_accum[i];
   }

void OCB_Encryption::update(secure_vector<byte>& buffer)
   {
   BOTAN_ASSERT(buffer.size() % BS == 0, "Input length is an even number of blocks");

   encrypt(&buffer[0], buffer.size() / BS);
   }

void OCB_Encryption::finish(secure_vector<byte>& buffer)
   {
   if(!buffer.empty())
      {
      const size_t final_full_blocks = buffer.size() / BS;
      const size_t remainder_bytes = buffer.size() - (final_full_blocks * BS);

      encrypt(&buffer[0], final_full_blocks);

      if(remainder_bytes)
         {
         BOTAN_ASSERT(remainder_bytes < BS, "Only a partial block left");
         byte* remainder = &buffer[buffer.size() - remainder_bytes];

         xor_buf(&m_checksum[0], &remainder[0], remainder_bytes);
         m_checksum[remainder_bytes] ^= 0x80;

         m_offset ^= m_L->star(); // Offset_*

         secure_vector<byte> buf(BS);
         m_cipher->encrypt(m_offset, buf);
         xor_buf(&remainder[0], &buf[0], remainder_bytes);
         }
      }

   // now compute the tag
   secure_vector<byte> mac = m_offset;
   mac ^= m_checksum;
   mac ^= m_L->dollar();

   m_cipher->encrypt(mac);

   mac ^= m_ad_hash;

   buffer += std::make_pair(&mac[0], tag_size());

   zeroise(m_checksum);
   zeroise(m_offset);
   m_block_index = 0;
   }

void OCB_Decryption::decrypt(byte buffer[], size_t blocks)
   {
   const L_computer& L = *m_L; // convenient name

   const size_t par_bytes = m_cipher->parallel_bytes();

   BOTAN_ASSERT(par_bytes % BS == 0, "Cipher is parallel in full blocks");

   const size_t par_blocks = par_bytes / BS;

   secure_vector<byte> csum_accum(par_bytes);
   secure_vector<byte> offsets(par_bytes);

   size_t blocks_left = blocks;

   while(blocks_left)
      {
      const size_t proc_blocks = std::min(blocks_left, par_blocks);
      const size_t proc_bytes = proc_blocks * BS;

      for(size_t i = 0; i != proc_blocks; ++i)
         { // could be done in parallel
         m_offset ^= L(ctz(++m_block_index));
         copy_mem(&offsets[BS*i], &m_offset[0], BS);
         }

      xor_buf(&buffer[0], &offsets[0], proc_bytes);

      m_cipher->decrypt_n(&buffer[0], &buffer[0], proc_blocks);

      xor_buf(&buffer[0], &offsets[0], proc_bytes);

      xor_buf(&csum_accum[0], &buffer[0], proc_bytes);

      buffer += proc_bytes;
      blocks_left -= proc_blocks;
      }

   // fold into checksum
   for(size_t i = 0; i != csum_accum.size(); ++i)
      m_checksum[i % BS] ^= csum_accum[i];
   }

void OCB_Decryption::update(secure_vector<byte>& buffer)
   {
   BOTAN_ASSERT(buffer.size() % BS == 0, "Input length is an even number of blocks");

   decrypt(&buffer[0], buffer.size() / BS);
   }

void OCB_Decryption::finish(secure_vector<byte>& buffer)
   {
   BOTAN_ASSERT(buffer.size() >= tag_size(), "We have the tag");

   const size_t remaining = buffer.size() - tag_size();

   if(remaining)
      {
      const size_t final_full_blocks = remaining / BS;
      const size_t final_bytes = remaining - (final_full_blocks * BS);

      decrypt(&buffer[0], final_full_blocks);

      if(final_bytes)
         {
         BOTAN_ASSERT(final_bytes < BS, "Only a partial block left");

         byte* remainder = &buffer[remaining - final_bytes];

         m_offset ^= m_L->star(); // Offset_*

         secure_vector<byte> pad(BS);
         m_cipher->encrypt(m_offset, pad); // P_*

         xor_buf(&remainder[0], &pad[0], final_bytes);

         xor_buf(&m_checksum[0], &remainder[0], final_bytes);
         m_checksum[final_bytes] ^= 0x80;
         }
      }

   // compute the mac
   secure_vector<byte> mac = m_offset;
   mac ^= m_checksum;
   mac ^= m_L->dollar();

   m_cipher->encrypt(mac);

   mac ^= m_ad_hash;

   // reset state
   zeroise(m_checksum);
   zeroise(m_offset);
   m_block_index = 0;

   // compare mac
   const byte* included_tag = &buffer[remaining];

   if(!same_mem(&mac[0], included_tag, tag_size()))
      throw Integrity_Failure("OCB tag check failed");

   // remove tag from end of message
   buffer.resize(remaining);
   }

}
