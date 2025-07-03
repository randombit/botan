/*
 * ISO-9796-2 - Digital signature schemes giving message recovery schemes 2 and 3
 * (C) 2016 Tobias Niemann, Hackmanit GmbH
 *     2025 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/iso9796.h>

#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hash_id.h>
#include <botan/internal/mgf1.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

std::vector<uint8_t> iso9796_encoding(std::span<const uint8_t> msg,
                                      size_t output_bits,
                                      std::unique_ptr<HashFunction>& hash,
                                      size_t salt_len,
                                      bool implicit,
                                      RandomNumberGenerator& rng) {
   const size_t output_length = (output_bits + 7) / 8;

   //set trailer length
   const size_t trailer_len = (implicit) ? 1 : 2;

   const size_t hash_len = hash->output_length();

   if(output_length <= hash_len + salt_len + trailer_len) {
      throw Encoding_Error("ISO9796-2::encoding_of: Output length is too small");
   }

   //calculate message capacity
   const size_t capacity = output_length - hash_len - salt_len - trailer_len - 1;

   //msg1 is the recoverable and hmsg2 is the hash of the unrecoverable message part.
   std::span<const uint8_t> msg1;
   const size_t msg1_len = std::min(capacity, msg.size());
   const size_t msg2_len = msg.size() - msg1_len;  // possibly zero
   msg1 = msg.first(msg1_len);

   hash->update(msg.subspan(msg1_len, msg2_len));  // possibly empty
   const std::vector<uint8_t> hmsg2 = hash->final_stdvec();

   //compute H(C||msg1 ||H(msg2)||S)
   const auto salt = rng.random_vec<std::vector<uint8_t>>(salt_len);
   hash->update_be(static_cast<uint64_t>(msg1_len) * 8);
   hash->update(msg1);
   hash->update(hmsg2);
   hash->update(salt);
   const std::vector<uint8_t> H = hash->final_stdvec();

   std::vector<uint8_t> EM(output_length);

   BufferStuffer stuffer(EM);
   stuffer.append(0x00, stuffer.remaining_capacity() - (hash_len + salt_len + trailer_len + msg1_len + 1));
   stuffer.append(0x01);
   stuffer.append(msg1);
   stuffer.append(salt);

   //apply mask
   mgf1_mask(*hash, H.data(), hash_len, EM.data(), output_length - hash_len - trailer_len);

   //clear the leftmost bit (confer bouncy castle)
   EM[0] &= 0x7F;

   stuffer.append(H);

   // set implicit/ISO trailer

   if(implicit) {
      stuffer.append(0xBC);
   } else {
      const uint8_t hash_id = ieee1363_hash_id(hash->name());
      if(hash_id == 0) {
         throw Encoding_Error("ISO-9796: no hash identifier for " + hash->name());
      }
      stuffer.append(hash_id);
      stuffer.append(0xCC);
   }

   BOTAN_ASSERT_NOMSG(stuffer.full());

   return EM;
}

bool iso9796_verification(std::span<const uint8_t> repr,
                          std::span<const uint8_t> raw,
                          size_t key_bits,
                          std::unique_ptr<HashFunction>& hash,
                          size_t salt_len) {
   const size_t hash_len = hash->output_length();
   const size_t KEY_BYTES = (key_bits + 7) / 8;

   if(repr.size() != KEY_BYTES) {
      return false;
   }
   //get trailer length
   size_t trailer_len;
   if(repr[repr.size() - 1] == 0xBC) {
      trailer_len = 1;
   } else {
      trailer_len = 2;

      uint8_t hash_id = ieee1363_hash_id(hash->name());
      if(hash_id == 0) {
         throw Decoding_Error("ISO-9796: no hash identifier for " + hash->name());
      }

      const uint8_t trailer_0 = repr[repr.size() - 2];
      const uint8_t trailer_1 = repr[repr.size() - 1];

      if(trailer_0 != hash_id || trailer_1 != 0xCC) {
         return false;
      }
   }

   std::vector<uint8_t> coded(repr.begin(), repr.end());

   CT::poison(coded.data(), coded.size());
   //remove mask
   uint8_t* DB = coded.data();
   const size_t DB_size = coded.size() - hash_len - trailer_len;

   const uint8_t* H = &coded[DB_size];

   mgf1_mask(*hash, H, hash_len, DB, DB_size);
   //clear the leftmost bit (confer bouncy castle)
   DB[0] &= 0x7F;

   //recover msg1 and salt
   size_t msg1_offset = 1;

   auto waiting_for_delim = CT::Mask<uint8_t>::set();
   auto bad_input = CT::Mask<uint8_t>::cleared();

   for(size_t j = 0; j < DB_size; ++j) {
      const auto is_zero = CT::Mask<uint8_t>::is_zero(DB[j]);
      const auto is_one = CT::Mask<uint8_t>::is_equal(DB[j], 0x01);

      const auto add_m = waiting_for_delim & is_zero;

      bad_input |= waiting_for_delim & ~(is_zero | is_one);
      msg1_offset += add_m.if_set_return(1);

      waiting_for_delim &= is_zero;
   }

   //invalid, if delimiter 0x01 was not found or msg1_offset is too big
   bad_input |= waiting_for_delim;

   const auto bad_offset = CT::Mask<size_t>::is_lt(coded.size(), trailer_len + hash_len + msg1_offset + salt_len);
   bad_input |= CT::Mask<uint8_t>(bad_offset);

   //in case that msg1_offset is too big, just continue with offset = 0.
   msg1_offset = CT::Mask<size_t>::expand(bad_input.value()).if_not_set_return(msg1_offset);

   CT::unpoison(coded.data(), coded.size());
   CT::unpoison(msg1_offset);

   std::vector<uint8_t> msg1(coded.begin() + msg1_offset, coded.end() - trailer_len - hash_len - salt_len);
   std::vector<uint8_t> salt(coded.begin() + msg1_offset + msg1.size(), coded.end() - trailer_len - hash_len);

   //compute H2(C||msg1||H(msg2)||S*). * indicates a recovered value
   const size_t capacity = (key_bits - 2 + 7) / 8 - hash_len - salt_len - trailer_len - 1;
   std::vector<uint8_t> msg1raw;
   if(raw.size() > capacity) {
      msg1raw = std::vector<uint8_t>(raw.begin(), raw.begin() + capacity);
      hash->update(std::span(raw).subspan(capacity));
   } else {
      msg1raw.assign(raw.begin(), raw.end());
   }
   const std::vector<uint8_t> hmsg2 = hash->final_stdvec();

   const uint64_t msg1rawLength = msg1raw.size();
   hash->update_be(msg1rawLength * 8);
   hash->update(msg1raw);
   hash->update(hmsg2);
   hash->update(salt);
   std::vector<uint8_t> H3 = hash->final_stdvec();

   //compute H3(C*||msg1*||H(msg2)||S*) * indicates a recovered value
   const uint64_t msg1_len = msg1.size();
   hash->update_be(msg1_len * 8);
   hash->update(msg1);
   hash->update(hmsg2);
   hash->update(salt);
   std::vector<uint8_t> H2 = hash->final_stdvec();

   //check if H3 == H2
   bad_input |= CT::is_not_equal(H3.data(), H2.data(), hash_len);

   CT::unpoison(bad_input);
   return (bad_input.as_bool() == false);
}

}  // namespace

/*
 *  ISO-9796-2 signature scheme 2
 *  DS 2 is probabilistic
 */
void ISO_9796_DS2::update(const uint8_t input[], size_t length) {
   //need to buffer message completely, before digest
   m_msg_buffer.insert(m_msg_buffer.end(), input, input + length);
}

/*
 * Return the raw (unencoded) data
 */
std::vector<uint8_t> ISO_9796_DS2::raw_data() {
   std::vector<uint8_t> retbuffer = m_msg_buffer;
   m_msg_buffer.clear();
   return retbuffer;
}

/*
 *  ISO-9796-2 scheme 2 encode operation
 */
std::vector<uint8_t> ISO_9796_DS2::encoding_of(std::span<const uint8_t> msg,
                                               size_t output_bits,
                                               RandomNumberGenerator& rng) {
   return iso9796_encoding(msg, output_bits, m_hash, m_salt_len, m_implicit, rng);
}

/*
 * ISO-9796-2 scheme 2 verify operation
 */
bool ISO_9796_DS2::verify(std::span<const uint8_t> repr, std::span<const uint8_t> raw, size_t key_bits) {
   return iso9796_verification(repr, raw, key_bits, m_hash, m_salt_len);
}

/*
 * Return the SCAN name
 */
std::string ISO_9796_DS2::name() const {
   return fmt("ISO_9796_DS2({},{},{})", m_hash->name(), (m_implicit ? "imp" : "exp"), m_salt_len);
}

/*
 *  ISO-9796-2 signature scheme 3
 *  DS 3 is deterministic and equals DS2 without salt
 */
void ISO_9796_DS3::update(const uint8_t input[], size_t length) {
   //need to buffer message completely, before digest
   m_msg_buffer.insert(m_msg_buffer.end(), input, input + length);
}

/*
 * Return the raw (unencoded) data
 */
std::vector<uint8_t> ISO_9796_DS3::raw_data() {
   std::vector<uint8_t> retbuffer = m_msg_buffer;
   m_msg_buffer.clear();
   return retbuffer;
}

/*
 *  ISO-9796-2 scheme 3 encode operation
 */
std::vector<uint8_t> ISO_9796_DS3::encoding_of(std::span<const uint8_t> msg,
                                               size_t output_bits,
                                               RandomNumberGenerator& rng) {
   return iso9796_encoding(msg, output_bits, m_hash, 0, m_implicit, rng);
}

/*
 * ISO-9796-2 scheme 3 verify operation
 */
bool ISO_9796_DS3::verify(std::span<const uint8_t> repr, std::span<const uint8_t> raw, size_t key_bits) {
   return iso9796_verification(repr, raw, key_bits, m_hash, 0);
}

/*
 * Return the SCAN name
 */
std::string ISO_9796_DS3::name() const {
   return fmt("ISO_9796_DS3({},{})", m_hash->name(), (m_implicit ? "imp" : "exp"));
}

}  // namespace Botan
