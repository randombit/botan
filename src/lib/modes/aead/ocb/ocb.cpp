/*
* OCB Mode
* (C) 2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ocb.h>
#include <botan/cmac.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

// Has to be in Botan namespace so unique_ptr can reference it
class L_computer
   {
   public:
      explicit L_computer(const BlockCipher& cipher)
         {
         m_L_star.resize(cipher.block_size());
         cipher.encrypt(m_L_star);
         m_L_dollar = poly_double(star());
         m_L.push_back(poly_double(dollar()));
         }

      const secure_vector<byte>& star() const { return m_L_star; }

      const secure_vector<byte>& dollar() const { return m_L_dollar; }

      const secure_vector<byte>& operator()(size_t i) const { return get(i); }

      const secure_vector<byte>& compute_offsets(secure_vector<byte>& offset,
                                                 size_t block_index,
                                                 size_t blocks) const
         {
         m_offset_buf.resize(blocks * 16);

         for(size_t i = 0; i != blocks; ++i)
            { // could be done in parallel
            offset ^= get(ctz(block_index + 1 + i));
            copy_mem(&m_offset_buf[16*i], offset.data(), 16);
            }

         return m_offset_buf;
         }

   private:
      const secure_vector<byte>& get(size_t i) const
         {
         while(m_L.size() <= i)
            m_L.push_back(poly_double(m_L.back()));

         return m_L.at(i);
         }

      secure_vector<byte> poly_double(const secure_vector<byte>& in) const
         {
         return CMAC::poly_double(in);
         }

      secure_vector<byte> m_L_dollar, m_L_star;
      mutable std::vector<secure_vector<byte>> m_L;
      mutable secure_vector<byte> m_offset_buf;
   };

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
      xor_buf(buf.data(), &ad[16*i], 16);

      cipher.encrypt(buf);

      sum ^= buf;
      }

   if(ad_remainder)
      {
      offset ^= L.star();

      buf = offset;
      xor_buf(buf.data(), &ad[16*ad_blocks], ad_remainder);
      buf[ad_len % 16] ^= 0x80;

      cipher.encrypt(buf);

      sum ^= buf;
      }

   return sum;
   }

}

OCB_Mode::OCB_Mode(BlockCipher* cipher, size_t tag_size) :
   m_cipher(cipher),
   m_checksum(m_cipher->parallel_bytes()),
   m_offset(16),
   m_ad_hash(16),
   m_tag_size(tag_size)
   {
   if(m_cipher->block_size() != 16)
      throw Invalid_Argument("OCB requires 128 bit cipher");

   if(m_tag_size % 4 != 0 || m_tag_size < 8 || m_tag_size > 16)
      throw Invalid_Argument("Invalid OCB tag length");
   }

OCB_Mode::~OCB_Mode() { /* for unique_ptr destructor */ }

void OCB_Mode::clear()
   {
   m_cipher->clear();
   m_L.reset(); // add clear here?
   reset();
   }

void OCB_Mode::reset()
   {
   m_block_index = 0;
   zeroise(m_ad_hash);
   zeroise(m_offset);
   zeroise(m_checksum);
   m_last_nonce.clear();
   m_stretch.clear();
   }

bool OCB_Mode::valid_nonce_length(size_t length) const
   {
   return (length > 0 && length < m_cipher->block_size());
   }

std::string OCB_Mode::name() const
   {
   return m_cipher->name() + "/OCB"; // include tag size
   }

size_t OCB_Mode::update_granularity() const
   {
   return m_cipher->parallel_bytes();
   }

Key_Length_Specification OCB_Mode::key_spec() const
   {
   return m_cipher->key_spec();
   }

void OCB_Mode::key_schedule(const byte key[], size_t length)
   {
   m_cipher->set_key(key, length);
   m_L.reset(new L_computer(*m_cipher));
   }

void OCB_Mode::set_associated_data(const byte ad[], size_t ad_len)
   {
   BOTAN_ASSERT(m_L, "A key was set");
   m_ad_hash = ocb_hash(*m_L, *m_cipher, ad, ad_len);
   }

secure_vector<byte>
OCB_Mode::update_nonce(const byte nonce[], size_t nonce_len)
   {
   BOTAN_ASSERT(nonce_len < 16, "OCB nonce is less than cipher block size");

   secure_vector<byte> nonce_buf(16);

   copy_mem(&nonce_buf[16 - nonce_len], nonce, nonce_len);
   nonce_buf[0] = ((tag_size() * 8) % 128) << 1;
   nonce_buf[16 - nonce_len - 1] = 1;

   const byte bottom = nonce_buf[16-1] & 0x3F;
   nonce_buf[16-1] &= 0xC0;

   const bool need_new_stretch = (m_last_nonce != nonce_buf);

   if(need_new_stretch)
      {
      m_last_nonce = nonce_buf;

      m_cipher->encrypt(nonce_buf);

      for(size_t i = 0; i != 16 / 2; ++i)
         nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i+1]);

      m_stretch = nonce_buf;
      }

   // now set the offset from stretch and bottom

   const size_t shift_bytes = bottom / 8;
   const size_t shift_bits  = bottom % 8;

   secure_vector<byte> offset(16);
   for(size_t i = 0; i != 16; ++i)
      {
      offset[i]  = (m_stretch[i+shift_bytes] << shift_bits);
      offset[i] |= (m_stretch[i+shift_bytes+1] >> (8-shift_bits));
      }

   return offset;
   }

void OCB_Mode::start_msg(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   BOTAN_ASSERT(m_L, "A key was set");

   m_offset = update_nonce(nonce, nonce_len);
   zeroise(m_checksum);
   m_block_index = 0;
   }

void OCB_Encryption::encrypt(byte buffer[], size_t blocks)
   {
   const size_t par_blocks = m_checksum.size() / 16;

   while(blocks)
      {
      const size_t proc_blocks = std::min(blocks, par_blocks);
      const size_t proc_bytes = proc_blocks * 16;

      const auto& offsets = m_L->compute_offsets(m_offset, m_block_index, proc_blocks);

      xor_buf(m_checksum.data(), buffer, proc_bytes);

      xor_buf(buffer, offsets.data(), proc_bytes);
      m_cipher->encrypt_n(buffer, buffer, proc_blocks);
      xor_buf(buffer, offsets.data(), proc_bytes);

      buffer += proc_bytes;
      blocks -= proc_blocks;
      m_block_index += proc_blocks;
      }
   }

size_t OCB_Encryption::process(uint8_t buf[], size_t sz)
   {
   BOTAN_ASSERT(sz % 16 == 0, "Invalid OCB input size");
   encrypt(buf, sz / 16);
   return sz;
   }

void OCB_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   if(sz)
      {
      const size_t final_full_blocks = sz / 16;
      const size_t remainder_bytes = sz - (final_full_blocks * 16);

      encrypt(buf, final_full_blocks);

      if(remainder_bytes)
         {
         BOTAN_ASSERT(remainder_bytes < 16, "Only a partial block left");
         byte* remainder = &buf[sz - remainder_bytes];

         xor_buf(m_checksum.data(), remainder, remainder_bytes);
         m_checksum[remainder_bytes] ^= 0x80;

         m_offset ^= m_L->star(); // Offset_*

         secure_vector<byte> zeros(16);
         m_cipher->encrypt(m_offset, zeros);
         xor_buf(remainder, zeros.data(), remainder_bytes);
         }
      }

   secure_vector<byte> checksum(16);

   // fold checksum
   for(size_t i = 0; i != m_checksum.size(); ++i)
      checksum[i % checksum.size()] ^= m_checksum[i];

   // now compute the tag
   secure_vector<byte> mac = m_offset;
   mac ^= checksum;
   mac ^= m_L->dollar();

   m_cipher->encrypt(mac);

   mac ^= m_ad_hash;

   buffer += std::make_pair(mac.data(), tag_size());

   zeroise(m_checksum);
   zeroise(m_offset);
   m_block_index = 0;
   }

void OCB_Decryption::decrypt(byte buffer[], size_t blocks)
   {
   const size_t par_bytes = m_cipher->parallel_bytes();

   BOTAN_ASSERT(par_bytes % 16 == 0, "Cipher is parallel in full blocks");

   const size_t par_blocks = par_bytes / 16;

   while(blocks)
      {
      const size_t proc_blocks = std::min(blocks, par_blocks);
      const size_t proc_bytes = proc_blocks * 16;

      const auto& offsets = m_L->compute_offsets(m_offset, m_block_index, proc_blocks);

      xor_buf(buffer, offsets.data(), proc_bytes);
      m_cipher->decrypt_n(buffer, buffer, proc_blocks);
      xor_buf(buffer, offsets.data(), proc_bytes);

      xor_buf(m_checksum.data(), buffer, proc_bytes);

      buffer += proc_bytes;
      blocks -= proc_blocks;
      m_block_index += proc_blocks;
      }
   }

size_t OCB_Decryption::process(uint8_t buf[], size_t sz)
   {
   BOTAN_ASSERT(sz % 16 == 0, "Invalid OCB input size");
   decrypt(buf, sz / 16);
   return sz;
   }

void OCB_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   BOTAN_ASSERT(sz >= tag_size(), "We have the tag");

   const size_t remaining = sz - tag_size();

   if(remaining)
      {
      const size_t final_full_blocks = remaining / 16;
      const size_t final_bytes = remaining - (final_full_blocks * 16);

      decrypt(buf, final_full_blocks);

      if(final_bytes)
         {
         BOTAN_ASSERT(final_bytes < 16, "Only a partial block left");

         byte* remainder = &buf[remaining - final_bytes];

         m_offset ^= m_L->star(); // Offset_*

         secure_vector<byte> pad(16);
         m_cipher->encrypt(m_offset, pad); // P_*

         xor_buf(remainder, pad.data(), final_bytes);

         xor_buf(m_checksum.data(), remainder, final_bytes);
         m_checksum[final_bytes] ^= 0x80;
         }
      }

   secure_vector<byte> checksum(16);

   // fold checksum
   for(size_t i = 0; i != m_checksum.size(); ++i)
      checksum[i % checksum.size()] ^= m_checksum[i];

   // compute the mac
   secure_vector<byte> mac = m_offset;
   mac ^= checksum;
   mac ^= m_L->dollar();

   m_cipher->encrypt(mac);

   mac ^= m_ad_hash;

   // reset state
   zeroise(m_checksum);
   zeroise(m_offset);
   m_block_index = 0;

   // compare mac
   const byte* included_tag = &buf[remaining];

   if(!same_mem(mac.data(), included_tag, tag_size()))
      throw Integrity_Failure("OCB tag check failed");

   // remove tag from end of message
   buffer.resize(remaining + offset);
   }

}
