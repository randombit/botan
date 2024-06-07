/*
* OCB Mode
* (C) 2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ocb.h>

#include <botan/block_cipher.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/poly_dbl.h>

namespace Botan {

// Has to be in Botan namespace so unique_ptr can reference it
class L_computer final {
   public:
      explicit L_computer(const BlockCipher& cipher) :
            m_BS(cipher.block_size()), m_max_blocks(cipher.parallel_bytes() / m_BS) {
         m_L_star.resize(m_BS);
         cipher.encrypt(m_L_star);
         m_L_dollar = poly_double(star());

         // Preallocate the m_L vector to the maximum expected size to avoid
         // re-allocations during runtime. This had caused a use-after-free in
         // earlier versions, due to references into this buffer becoming stale
         // in `compute_offset()`, after calling `get()` in the hot path.
         //
         // Note, that the list member won't be pre-allocated, so the expected
         // memory overhead is negligible.
         //
         // See also https://github.com/randombit/botan/issues/3812
         m_L.reserve(31);
         m_L.push_back(poly_double(dollar()));

         while(m_L.size() < 8) {
            m_L.push_back(poly_double(m_L.back()));
         }

         m_offset_buf.resize(m_BS * m_max_blocks);
      }

      void init(const secure_vector<uint8_t>& offset) { m_offset = offset; }

      bool initialized() const { return m_offset.empty() == false; }

      const secure_vector<uint8_t>& star() const { return m_L_star; }

      const secure_vector<uint8_t>& dollar() const { return m_L_dollar; }

      const secure_vector<uint8_t>& offset() const { return m_offset; }

      const secure_vector<uint8_t>& get(size_t i) const {
         while(m_L.size() <= i) {
            m_L.push_back(poly_double(m_L.back()));
         }

         return m_L[i];
      }

      const uint8_t* compute_offsets(size_t block_index, size_t blocks) {
         BOTAN_ASSERT(blocks <= m_max_blocks, "OCB offsets");

         uint8_t* offsets = m_offset_buf.data();

         if(block_index % 4 == 0) {
            const secure_vector<uint8_t>& L0 = get(0);
            const secure_vector<uint8_t>& L1 = get(1);

            while(blocks >= 4) {
               // ntz(4*i+1) == 0
               // ntz(4*i+2) == 1
               // ntz(4*i+3) == 0
               block_index += 4;
               const size_t ntz4 = var_ctz32(static_cast<uint32_t>(block_index));

               xor_buf(offsets, m_offset.data(), L0.data(), m_BS);
               offsets += m_BS;

               xor_buf(offsets, offsets - m_BS, L1.data(), m_BS);
               offsets += m_BS;

               xor_buf(m_offset.data(), L1.data(), m_BS);
               copy_mem(offsets, m_offset.data(), m_BS);
               offsets += m_BS;

               xor_buf(m_offset.data(), get(ntz4).data(), m_BS);
               copy_mem(offsets, m_offset.data(), m_BS);
               offsets += m_BS;

               blocks -= 4;
            }
         }

         for(size_t i = 0; i != blocks; ++i) {  // could be done in parallel
            const size_t ntz = var_ctz32(static_cast<uint32_t>(block_index + i + 1));
            xor_buf(m_offset.data(), get(ntz).data(), m_BS);
            copy_mem(offsets, m_offset.data(), m_BS);
            offsets += m_BS;
         }

         return m_offset_buf.data();
      }

   private:
      static secure_vector<uint8_t> poly_double(const secure_vector<uint8_t>& in) {
         secure_vector<uint8_t> out(in.size());
         poly_double_n(out.data(), in.data(), out.size());
         return out;
      }

      const size_t m_BS, m_max_blocks;
      secure_vector<uint8_t> m_L_dollar, m_L_star;
      secure_vector<uint8_t> m_offset;
      mutable std::vector<secure_vector<uint8_t>> m_L;
      secure_vector<uint8_t> m_offset_buf;
};

namespace {

/*
* OCB's HASH
*/
secure_vector<uint8_t> ocb_hash(const L_computer& L, const BlockCipher& cipher, const uint8_t ad[], size_t ad_len) {
   const size_t BS = cipher.block_size();
   secure_vector<uint8_t> sum(BS);
   secure_vector<uint8_t> offset(BS);

   secure_vector<uint8_t> buf(BS);

   const size_t ad_blocks = (ad_len / BS);
   const size_t ad_remainder = (ad_len % BS);

   for(size_t i = 0; i != ad_blocks; ++i) {
      // this loop could run in parallel
      offset ^= L.get(var_ctz32(static_cast<uint32_t>(i + 1)));
      buf = offset;
      xor_buf(buf.data(), &ad[BS * i], BS);
      cipher.encrypt(buf);
      sum ^= buf;
   }

   if(ad_remainder) {
      offset ^= L.star();
      buf = offset;
      xor_buf(buf.data(), &ad[BS * ad_blocks], ad_remainder);
      buf[ad_remainder] ^= 0x80;
      cipher.encrypt(buf);
      sum ^= buf;
   }

   return sum;
}

}  // namespace

OCB_Mode::OCB_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size) :
      m_cipher(std::move(cipher)),
      m_checksum(m_cipher->parallel_bytes()),
      m_ad_hash(m_cipher->block_size()),
      m_tag_size(tag_size),
      m_block_size(m_cipher->block_size()),
      m_par_blocks(m_cipher->parallel_bytes() / m_block_size) {
   const size_t BS = block_size();

   /*
   * draft-krovetz-ocb-wide-d1 specifies OCB for several other block
   * sizes but only 128, 192, 256 and 512 bit are currently supported
   * by this implementation.
   */
   BOTAN_ARG_CHECK(BS == 16 || BS == 24 || BS == 32 || BS == 64, "Invalid block size for OCB");

   BOTAN_ARG_CHECK(m_tag_size % 4 == 0 && m_tag_size >= 8 && m_tag_size <= BS && m_tag_size <= 32,
                   "Invalid OCB tag length");
}

OCB_Mode::~OCB_Mode() = default;

void OCB_Mode::clear() {
   m_cipher->clear();
   m_L.reset();  // add clear here?
   reset();
}

void OCB_Mode::reset() {
   m_block_index = 0;
   zeroise(m_ad_hash);
   zeroise(m_checksum);
   m_last_nonce.clear();
   m_stretch.clear();
}

bool OCB_Mode::valid_nonce_length(size_t length) const {
   if(length == 0) {
      return false;
   }
   if(block_size() == 16) {
      return length < 16;
   } else {
      return length < (block_size() - 1);
   }
}

std::string OCB_Mode::name() const {
   return m_cipher->name() + "/OCB";  // include tag size?
}

size_t OCB_Mode::update_granularity() const {
   return block_size();
}

size_t OCB_Mode::ideal_granularity() const {
   return (m_par_blocks * block_size());
}

Key_Length_Specification OCB_Mode::key_spec() const {
   return m_cipher->key_spec();
}

bool OCB_Mode::has_keying_material() const {
   return m_cipher->has_keying_material();
}

void OCB_Mode::key_schedule(std::span<const uint8_t> key) {
   m_cipher->set_key(key);
   m_L = std::make_unique<L_computer>(*m_cipher);
}

void OCB_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "OCB: cannot handle non-zero index in set_associated_data_n");
   assert_key_material_set();
   m_ad_hash = ocb_hash(*m_L, *m_cipher, ad.data(), ad.size());
}

const secure_vector<uint8_t>& OCB_Mode::update_nonce(const uint8_t nonce[], size_t nonce_len) {
   const size_t BS = block_size();

   BOTAN_ASSERT(BS == 16 || BS == 24 || BS == 32 || BS == 64, "OCB block size is supported");

   // NOLINTNEXTLINE(readability-avoid-nested-conditional-operator)
   const size_t MASKLEN = (BS == 16 ? 6 : ((BS == 24) ? 7 : 8));

   const uint8_t BOTTOM_MASK = static_cast<uint8_t>((static_cast<uint16_t>(1) << MASKLEN) - 1);

   m_nonce_buf.resize(BS);
   clear_mem(&m_nonce_buf[0], m_nonce_buf.size());

   copy_mem(&m_nonce_buf[BS - nonce_len], nonce, nonce_len);
   m_nonce_buf[0] = static_cast<uint8_t>(((tag_size() * 8) % (BS * 8)) << (BS <= 16 ? 1 : 0));

   m_nonce_buf[BS - nonce_len - 1] ^= 1;

   const uint8_t bottom = m_nonce_buf[BS - 1] & BOTTOM_MASK;
   m_nonce_buf[BS - 1] &= ~BOTTOM_MASK;

   const bool need_new_stretch = (m_last_nonce != m_nonce_buf);

   if(need_new_stretch) {
      m_last_nonce = m_nonce_buf;

      m_cipher->encrypt(m_nonce_buf);

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
      if(BS == 16) {
         for(size_t i = 0; i != BS / 2; ++i) {
            m_nonce_buf.push_back(m_nonce_buf[i] ^ m_nonce_buf[i + 1]);
         }
      } else if(BS == 24) {
         for(size_t i = 0; i != 16; ++i) {
            m_nonce_buf.push_back(m_nonce_buf[i] ^ m_nonce_buf[i + 5]);
         }
      } else if(BS == 32) {
         for(size_t i = 0; i != BS; ++i) {
            m_nonce_buf.push_back(m_nonce_buf[i] ^ (m_nonce_buf[i] << 1) ^ (m_nonce_buf[i + 1] >> 7));
         }
      } else if(BS == 64) {
         for(size_t i = 0; i != BS / 2; ++i) {
            m_nonce_buf.push_back(m_nonce_buf[i] ^ m_nonce_buf[i + 22]);
         }
      }

      m_stretch = m_nonce_buf;
   }

   // now set the offset from stretch and bottom
   const size_t shift_bytes = bottom / 8;
   const size_t shift_bits = bottom % 8;

   BOTAN_ASSERT(m_stretch.size() >= BS + shift_bytes + 1, "Size ok");

   m_offset.resize(BS);
   for(size_t i = 0; i != BS; ++i) {
      m_offset[i] = (m_stretch[i + shift_bytes] << shift_bits);
      m_offset[i] |= (m_stretch[i + shift_bytes + 1] >> (8 - shift_bits));
   }

   return m_offset;
}

void OCB_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   assert_key_material_set();

   m_L->init(update_nonce(nonce, nonce_len));
   zeroise(m_checksum);
   m_block_index = 0;
}

void OCB_Encryption::encrypt(uint8_t buffer[], size_t blocks) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(m_L->initialized());

   const size_t BS = block_size();

   while(blocks) {
      const size_t proc_blocks = std::min(blocks, par_blocks());
      const size_t proc_bytes = proc_blocks * BS;

      const uint8_t* offsets = m_L->compute_offsets(m_block_index, proc_blocks);

      xor_buf(m_checksum.data(), buffer, proc_bytes);

      m_cipher->encrypt_n_xex(buffer, offsets, proc_blocks);

      buffer += proc_bytes;
      blocks -= proc_blocks;
      m_block_index += proc_blocks;
   }
}

size_t OCB_Encryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_ARG_CHECK(sz % update_granularity() == 0, "Invalid OCB input size");
   encrypt(buf, sz / block_size());
   return sz;
}

void OCB_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(m_L->initialized());

   const size_t BS = block_size();

   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   secure_vector<uint8_t> mac(BS);

   if(sz) {
      const size_t final_full_blocks = sz / BS;
      const size_t remainder_bytes = sz - (final_full_blocks * BS);

      encrypt(buf, final_full_blocks);
      mac = m_L->offset();

      if(remainder_bytes) {
         BOTAN_ASSERT(remainder_bytes < BS, "Only a partial block left");
         uint8_t* remainder = &buf[sz - remainder_bytes];

         xor_buf(m_checksum.data(), remainder, remainder_bytes);
         m_checksum[remainder_bytes] ^= 0x80;

         // Offset_*
         mac ^= m_L->star();

         secure_vector<uint8_t> pad(BS);
         m_cipher->encrypt(mac, pad);
         xor_buf(remainder, pad.data(), remainder_bytes);
      }
   } else {
      mac = m_L->offset();
   }

   // now compute the tag

   // fold checksum
   for(size_t i = 0; i != m_checksum.size(); i += BS) {
      xor_buf(mac.data(), m_checksum.data() + i, BS);
   }

   xor_buf(mac.data(), m_L->dollar().data(), BS);
   m_cipher->encrypt(mac);
   xor_buf(mac.data(), m_ad_hash.data(), BS);

   buffer += std::make_pair(mac.data(), tag_size());

   zeroise(m_checksum);
   m_block_index = 0;
}

void OCB_Decryption::decrypt(uint8_t buffer[], size_t blocks) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(m_L->initialized());

   const size_t BS = block_size();

   while(blocks) {
      const size_t proc_blocks = std::min(blocks, par_blocks());
      const size_t proc_bytes = proc_blocks * BS;

      const uint8_t* offsets = m_L->compute_offsets(m_block_index, proc_blocks);

      m_cipher->decrypt_n_xex(buffer, offsets, proc_blocks);

      xor_buf(m_checksum.data(), buffer, proc_bytes);

      buffer += proc_bytes;
      blocks -= proc_blocks;
      m_block_index += proc_blocks;
   }
}

size_t OCB_Decryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_ARG_CHECK(sz % update_granularity() == 0, "Invalid OCB input size");
   decrypt(buf, sz / block_size());
   return sz;
}

void OCB_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(m_L->initialized());

   const size_t BS = block_size();

   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ARG_CHECK(sz >= tag_size(), "input did not include the tag");

   const size_t remaining = sz - tag_size();

   secure_vector<uint8_t> mac(BS);

   if(remaining) {
      const size_t final_full_blocks = remaining / BS;
      const size_t final_bytes = remaining - (final_full_blocks * BS);

      decrypt(buf, final_full_blocks);
      mac ^= m_L->offset();

      if(final_bytes) {
         BOTAN_ASSERT(final_bytes < BS, "Only a partial block left");

         uint8_t* remainder = &buf[remaining - final_bytes];

         mac ^= m_L->star();
         secure_vector<uint8_t> pad(BS);
         m_cipher->encrypt(mac, pad);  // P_*
         xor_buf(remainder, pad.data(), final_bytes);

         xor_buf(m_checksum.data(), remainder, final_bytes);
         m_checksum[final_bytes] ^= 0x80;
      }
   } else {
      mac = m_L->offset();
   }

   // compute the mac

   // fold checksum
   for(size_t i = 0; i != m_checksum.size(); i += BS) {
      xor_buf(mac.data(), m_checksum.data() + i, BS);
   }

   mac ^= m_L->dollar();
   m_cipher->encrypt(mac);
   mac ^= m_ad_hash;

   // reset state
   zeroise(m_checksum);
   m_block_index = 0;

   // compare mac
   const uint8_t* included_tag = &buf[remaining];

   if(!CT::is_equal(mac.data(), included_tag, tag_size()).as_bool()) {
      throw Invalid_Authentication_Tag("OCB tag check failed");
   }

   // remove tag from end of message
   buffer.resize(remaining + offset);
}

}  // namespace Botan
