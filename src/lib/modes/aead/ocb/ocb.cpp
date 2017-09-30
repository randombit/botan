/*
* OCB Mode
* (C) 2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ocb.h>
#include <botan/block_cipher.h>
#include <botan/internal/poly_dbl.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

// Has to be in Botan namespace so unique_ptr can reference it
class L_computer final
   {
   public:
      explicit L_computer(const BlockCipher& cipher)
         {
         m_L_star.resize(cipher.block_size());
         cipher.encrypt(m_L_star);
         m_L_dollar = poly_double(star());
         m_L.push_back(poly_double(dollar()));
         }

      const secure_vector<uint8_t>& star() const { return m_L_star; }

      const secure_vector<uint8_t>& dollar() const { return m_L_dollar; }

      const secure_vector<uint8_t>& operator()(size_t i) const { return get(i); }

      const secure_vector<uint8_t>&
      compute_offsets(secure_vector<uint8_t>& offset,
                      size_t block_index,
                      size_t blocks,
                      size_t BS) const
         {
         m_offset_buf.resize(blocks * BS);

         for(size_t i = 0; i != blocks; ++i)
            { // could be done in parallel
            offset ^= get(ctz(block_index + 1 + i));
            copy_mem(&m_offset_buf[BS*i], offset.data(), BS);
            }

         return m_offset_buf;
         }

   private:
      const secure_vector<uint8_t>& get(size_t i) const
         {
         while(m_L.size() <= i)
            m_L.push_back(poly_double(m_L.back()));

         return m_L.at(i);
         }

      secure_vector<uint8_t> poly_double(const secure_vector<uint8_t>& in) const
         {
         secure_vector<uint8_t> out(in.size());
         poly_double_n(out.data(), in.data(), out.size());
         return out;
         }

      secure_vector<uint8_t> m_L_dollar, m_L_star;
      mutable std::vector<secure_vector<uint8_t>> m_L;
      mutable secure_vector<uint8_t> m_offset_buf;
   };

namespace {

/*
* OCB's HASH
*/
secure_vector<uint8_t> ocb_hash(const L_computer& L,
                                const BlockCipher& cipher,
                                const uint8_t ad[], size_t ad_len)
   {
   const size_t BS = cipher.block_size();
   secure_vector<uint8_t> sum(BS);
   secure_vector<uint8_t> offset(BS);

   secure_vector<uint8_t> buf(BS);

   const size_t ad_blocks = (ad_len / BS);
   const size_t ad_remainder = (ad_len % BS);

   for(size_t i = 0; i != ad_blocks; ++i)
      {
      // this loop could run in parallel
      offset ^= L(ctz(i+1));

      buf = offset;
      xor_buf(buf.data(), &ad[BS*i], BS);

      cipher.encrypt(buf);

      sum ^= buf;
      }

   if(ad_remainder)
      {
      offset ^= L.star();

      buf = offset;
      xor_buf(buf.data(), &ad[BS*ad_blocks], ad_remainder);
      buf[ad_len % BS] ^= 0x80;

      cipher.encrypt(buf);

      sum ^= buf;
      }

   return sum;
   }

}

OCB_Mode::OCB_Mode(BlockCipher* cipher, size_t tag_size) :
   m_cipher(cipher),
   m_checksum(m_cipher->parallel_bytes()),
   m_offset(m_cipher->block_size()),
   m_ad_hash(m_cipher->block_size()),
   m_tag_size(tag_size)
   {
   const size_t BS = m_cipher->block_size();

   /*
   * draft-krovetz-ocb-wide-d1 specifies OCB for several other block
   * sizes but only 128, 192, 256 and 512 bit are currently supported
   * by this implementation.
   */
   if(BS != 16 && BS != 24 && BS != 32 && BS != 64)
      throw Invalid_Argument("OCB does not support cipher " + m_cipher->name());

   if(m_tag_size % 4 != 0 || m_tag_size < 8 || m_tag_size > BS || m_tag_size > 32)
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
   if(length == 0)
      return false;
   if(m_cipher->block_size() == 16)
      return length < 16;
   else
      return length < (m_cipher->block_size() - 1);
   }

std::string OCB_Mode::name() const
   {
   return m_cipher->name() + "/OCB"; // include tag size?
   }

size_t OCB_Mode::update_granularity() const
   {
   return m_cipher->parallel_bytes();
   }

Key_Length_Specification OCB_Mode::key_spec() const
   {
   return m_cipher->key_spec();
   }

void OCB_Mode::key_schedule(const uint8_t key[], size_t length)
   {
   m_cipher->set_key(key, length);
   m_L.reset(new L_computer(*m_cipher));
   }

void OCB_Mode::set_associated_data(const uint8_t ad[], size_t ad_len)
   {
   BOTAN_ASSERT(m_L, "A key was set");
   m_ad_hash = ocb_hash(*m_L, *m_cipher, ad, ad_len);
   }

secure_vector<uint8_t>
OCB_Mode::update_nonce(const uint8_t nonce[], size_t nonce_len)
   {
   const size_t BS = m_cipher->block_size();

   BOTAN_ASSERT(BS == 16 || BS == 24 || BS == 32 || BS == 64,
                "OCB block size is supported");

   const size_t MASKLEN = (BS == 16 ? 6 : ((BS == 24) ? 7 : 8));

   const uint8_t BOTTOM_MASK =
      static_cast<uint8_t>((static_cast<uint16_t>(1) << MASKLEN) - 1);

   secure_vector<uint8_t> nonce_buf(BS);

   copy_mem(&nonce_buf[BS - nonce_len], nonce, nonce_len);
   nonce_buf[0] = static_cast<uint8_t>(((tag_size()*8) % (BS*8)) << (BS <= 16 ? 1 : 0));

   nonce_buf[BS - nonce_len - 1] ^= 1;

   const uint8_t bottom = nonce_buf[BS-1] & BOTTOM_MASK;
   nonce_buf[BS-1] &= ~BOTTOM_MASK;

   const bool need_new_stretch = (m_last_nonce != nonce_buf);

   if(need_new_stretch)
      {
      m_last_nonce = nonce_buf;

      m_cipher->encrypt(nonce_buf);

      /*
      The loop bounds (BS vs BS/2) are derived from the relation
      between the block size and the MASKLEN. Using the terminology
      of draft-krovetz-ocb-wide, we have to derive enough bits in
      ShiftedKtop to read up to BLOCKLEN+bottom bits from Stretch.

                 +----------+---------+-------+---------+
                 | BLOCKLEN | RESIDUE | SHIFT | MASKLEN |
                 +----------+---------+-------+---------+
                 |       32 |     141 |    17 |    4    |
                 |       64 |      27 |    25 |    5    |
                 |       96 |    1601 |    33 |    6    |
                 |      128 |     135 |     8 |    6    |
                 |      192 |     135 |    40 |    7    |
                 |      256 |    1061 |     1 |    8    |
                 |      384 |    4109 |    80 |    8    |
                 |      512 |     293 |   176 |    8    |
                 |     1024 |  524355 |   352 |    9    |
                 +----------+---------+-------+---------+
      */
      if(BS == 16)
         {
         for(size_t i = 0; i != BS / 2; ++i)
            nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i+1]);
         }
      else if(BS == 24)
         {
         for(size_t i = 0; i != 16; ++i)
            nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i+5]);
         }
      else if(BS == 32)
         {
         for(size_t i = 0; i != BS; ++i)
            nonce_buf.push_back(nonce_buf[i] ^ (nonce_buf[i] << 1) ^ (nonce_buf[i+1] >> 7));
         }
      else if(BS == 64)
         {
         for(size_t i = 0; i != BS / 2; ++i)
            nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i+22]);
         }

      m_stretch = nonce_buf;
      }

   // now set the offset from stretch and bottom
   const size_t shift_bytes = bottom / 8;
   const size_t shift_bits  = bottom % 8;

   BOTAN_ASSERT(m_stretch.size() >= BS + shift_bytes + 1, "Size ok");

   secure_vector<uint8_t> offset(BS);
   for(size_t i = 0; i != BS; ++i)
      {
      offset[i]  = (m_stretch[i+shift_bytes] << shift_bits);
      offset[i] |= (m_stretch[i+shift_bytes+1] >> (8-shift_bits));
      }

   return offset;
   }

void OCB_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   BOTAN_ASSERT(m_L, "A key was set");

   m_offset = update_nonce(nonce, nonce_len);
   zeroise(m_checksum);
   m_block_index = 0;
   }

void OCB_Encryption::encrypt(uint8_t buffer[], size_t blocks)
   {
   const size_t BS = m_cipher->block_size();
   const size_t par_blocks = m_checksum.size() / BS;

   while(blocks)
      {
      const size_t proc_blocks = std::min(blocks, par_blocks);
      const size_t proc_bytes = proc_blocks * BS;

      BOTAN_ASSERT(m_L, "A key was set");

      const auto& offsets = m_L->compute_offsets(m_offset, m_block_index, proc_blocks, BS);

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
   const size_t BS = m_cipher->block_size();
   BOTAN_ASSERT(sz % BS == 0, "Invalid OCB input size");
   encrypt(buf, sz / BS);
   return sz;
   }

void OCB_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   const size_t BS = m_cipher->block_size();

   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   if(sz)
      {
      const size_t final_full_blocks = sz / BS;
      const size_t remainder_bytes = sz - (final_full_blocks * BS);

      encrypt(buf, final_full_blocks);

      if(remainder_bytes)
         {
         BOTAN_ASSERT(remainder_bytes < BS, "Only a partial block left");
         uint8_t* remainder = &buf[sz - remainder_bytes];

         xor_buf(m_checksum.data(), remainder, remainder_bytes);
         m_checksum[remainder_bytes] ^= 0x80;

         m_offset ^= m_L->star(); // Offset_*

         secure_vector<uint8_t> zeros(BS);
         m_cipher->encrypt(m_offset, zeros);
         xor_buf(remainder, zeros.data(), remainder_bytes);
         }
      }

   secure_vector<uint8_t> checksum(BS);

   // fold checksum
   for(size_t i = 0; i != m_checksum.size(); ++i)
      checksum[i % checksum.size()] ^= m_checksum[i];

   // now compute the tag
   secure_vector<uint8_t> mac = m_offset;
   mac ^= checksum;
   mac ^= m_L->dollar();
   m_cipher->encrypt(mac);
   mac ^= m_ad_hash;

   buffer += std::make_pair(mac.data(), tag_size());

   zeroise(m_checksum);
   zeroise(m_offset);
   m_block_index = 0;
   }

void OCB_Decryption::decrypt(uint8_t buffer[], size_t blocks)
   {
   const size_t BS = m_cipher->block_size();
   const size_t par_bytes = m_cipher->parallel_bytes();

   BOTAN_ASSERT(par_bytes % BS == 0, "Cipher is parallel in full blocks");

   const size_t par_blocks = par_bytes / BS;

   while(blocks)
      {
      const size_t proc_blocks = std::min(blocks, par_blocks);
      const size_t proc_bytes = proc_blocks * BS;

      const auto& offsets = m_L->compute_offsets(m_offset, m_block_index, proc_blocks, BS);

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
   const size_t BS = m_cipher->block_size();
   BOTAN_ASSERT(sz % BS == 0, "Invalid OCB input size");
   decrypt(buf, sz / BS);
   return sz;
   }

void OCB_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   const size_t BS = m_cipher->block_size();

   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ASSERT(sz >= tag_size(), "We have the tag");

   const size_t remaining = sz - tag_size();

   if(remaining)
      {
      const size_t final_full_blocks = remaining / BS;
      const size_t final_bytes = remaining - (final_full_blocks * BS);

      decrypt(buf, final_full_blocks);

      if(final_bytes)
         {
         BOTAN_ASSERT(final_bytes < BS, "Only a partial block left");

         uint8_t* remainder = &buf[remaining - final_bytes];

         m_offset ^= m_L->star(); // Offset_*

         secure_vector<uint8_t> pad(BS);
         m_cipher->encrypt(m_offset, pad); // P_*

         xor_buf(remainder, pad.data(), final_bytes);

         xor_buf(m_checksum.data(), remainder, final_bytes);
         m_checksum[final_bytes] ^= 0x80;
         }
      }

   secure_vector<uint8_t> checksum(BS);

   // fold checksum
   for(size_t i = 0; i != m_checksum.size(); ++i)
      checksum[i % checksum.size()] ^= m_checksum[i];

   // compute the mac
   secure_vector<uint8_t> mac = m_offset;
   mac ^= checksum;
   mac ^= m_L->dollar();

   m_cipher->encrypt(mac);

   mac ^= m_ad_hash;

   // reset state
   zeroise(m_checksum);
   zeroise(m_offset);
   m_block_index = 0;

   // compare mac
   const uint8_t* included_tag = &buf[remaining];

   if(!constant_time_compare(mac.data(), included_tag, tag_size()))
      throw Integrity_Failure("OCB tag check failed");

   // remove tag from end of message
   buffer.resize(remaining + offset);
   }

}
