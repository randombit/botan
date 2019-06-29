/*
 * ISO-9796-2 - Digital signature schemes giving message recovery schemes 2 and 3
 * (C) 2016 Tobias Niemann, Hackmanit GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/iso9796.h>
#include <botan/rng.h>
#include <botan/exceptn.h>
#include <botan/mgf1.h>
#include <botan/hash_id.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

namespace {

secure_vector<uint8_t> iso9796_encoding(const secure_vector<uint8_t>& msg,
                                        size_t output_bits,
                                        std::unique_ptr<HashFunction>& hash,
                                        size_t SALT_SIZE,
                                        bool implicit,
                                        RandomNumberGenerator& rng)
   {
   const size_t output_length = (output_bits + 7) / 8;

   //set trailer length
   size_t tLength = 1;
   if(!implicit)
      {
      tLength = 2;
      }
   const size_t HASH_SIZE = hash->output_length();

   if(output_length <= HASH_SIZE + SALT_SIZE + tLength)
      {
      throw Encoding_Error("ISO9796-2::encoding_of: Output length is too small");
      }

   //calculate message capacity
   const size_t capacity = output_length - HASH_SIZE - SALT_SIZE - tLength - 1;

   //msg1 is the recoverable and msg2 the unrecoverable message part.
   secure_vector<uint8_t> msg1;
   secure_vector<uint8_t> msg2;
   if(msg.size() > capacity)
      {
      msg1 = secure_vector<uint8_t>(msg.begin(), msg.begin() + capacity);
      msg2 = secure_vector<uint8_t>(msg.begin() + capacity, msg.end());
      hash->update(msg2);
      }
   else
      {
      msg1 = msg;
      }
   msg2 = hash->final();

   //compute H(C||msg1 ||H(msg2)||S)
   const size_t msgLength = msg1.size();
   secure_vector<uint8_t> salt = rng.random_vec(SALT_SIZE);
   hash->update_be(static_cast<uint64_t>(msgLength) * 8);
   hash->update(msg1);
   hash->update(msg2);
   hash->update(salt);
   secure_vector<uint8_t> H = hash->final();

   secure_vector<uint8_t> EM(output_length);

   //compute message offset.
   const size_t offset = output_length - HASH_SIZE - SALT_SIZE - tLength - msgLength - 1;

   //insert message border (0x01), msg1 and salt into the output buffer
   EM[offset] = 0x01;
   buffer_insert(EM, offset + 1, msg1);
   buffer_insert(EM, offset + 1 + msgLength, salt);

   //apply mask
   mgf1_mask(*hash, H.data(), HASH_SIZE, EM.data(),
             output_length - HASH_SIZE - tLength);
   buffer_insert(EM, output_length - HASH_SIZE - tLength, H);
   //set implicit/ISO trailer
   if(!implicit)
      {
      uint8_t hash_id = ieee1363_hash_id(hash->name());
      if(!hash_id)
         {
         throw Encoding_Error("ISO9796-2::encoding_of: no hash identifier for " + hash->name());
         }
      EM[output_length - 1] = 0xCC;
      EM[output_length - 2] = hash_id;

      }
   else
      {
      EM[output_length - 1] = 0xBC;
      }
   //clear the leftmost bit (confer bouncy castle)
   EM[0] &= 0x7F;

   return EM;
   }

bool iso9796_verification(const secure_vector<uint8_t>& const_coded,
                          const secure_vector<uint8_t>& raw, size_t key_bits, std::unique_ptr<HashFunction>& hash, size_t SALT_SIZE)
   {
   const size_t HASH_SIZE = hash->output_length();
   const size_t KEY_BYTES = (key_bits + 7) / 8;

   if(const_coded.size() != KEY_BYTES)
      {
      return false;
      }
   //get trailer length
   size_t tLength;
   if(const_coded[const_coded.size() - 1] == 0xBC)
      {
      tLength = 1;
      }
   else
      {
      uint8_t hash_id = ieee1363_hash_id(hash->name());
      if((!const_coded[const_coded.size() - 2]) || (const_coded[const_coded.size() - 2] != hash_id) ||
            (const_coded[const_coded.size() - 1] != 0xCC))
         {
         return false; //in case of wrong ISO trailer.
         }
      tLength = 2;
      }

   secure_vector<uint8_t> coded = const_coded;

   CT::poison(coded.data(), coded.size());
   //remove mask
   uint8_t* DB = coded.data();
   const size_t DB_size = coded.size() - HASH_SIZE - tLength;

   const uint8_t* H = &coded[DB_size];

   mgf1_mask(*hash, H, HASH_SIZE, DB, DB_size);
   //clear the leftmost bit (confer bouncy castle)
   DB[0] &= 0x7F;

   //recover msg1 and salt
   size_t msg1_offset = 1;

   auto waiting_for_delim = CT::Mask<uint8_t>::set();
   auto bad_input = CT::Mask<uint8_t>::cleared();

   for(size_t j = 0; j < DB_size; ++j)
      {
      const auto is_zero = CT::Mask<uint8_t>::is_zero(DB[j]);
      const auto is_one = CT::Mask<uint8_t>::is_equal(DB[j], 0x01);

      const auto add_m = waiting_for_delim & is_zero;

      bad_input |= waiting_for_delim & ~(is_zero | is_one);
      msg1_offset += add_m.if_set_return(1);

      waiting_for_delim &= is_zero;
      }

   //invalid, if delimiter 0x01 was not found or msg1_offset is too big
   bad_input |= waiting_for_delim;
   bad_input |= CT::Mask<size_t>::is_lt(coded.size(), tLength + HASH_SIZE + msg1_offset + SALT_SIZE);

   //in case that msg1_offset is too big, just continue with offset = 0.
   msg1_offset = CT::Mask<size_t>::expand(bad_input.value()).if_not_set_return(msg1_offset);

   CT::unpoison(coded.data(), coded.size());
   CT::unpoison(msg1_offset);

   secure_vector<uint8_t> msg1(coded.begin() + msg1_offset,
                            coded.end() - tLength - HASH_SIZE - SALT_SIZE);
   secure_vector<uint8_t> salt(coded.begin() + msg1_offset + msg1.size(),
                            coded.end() - tLength - HASH_SIZE);

   //compute H2(C||msg1||H(msg2)||S*). * indicates a recovered value
   const size_t capacity = (key_bits - 2 + 7) / 8 - HASH_SIZE - SALT_SIZE - tLength - 1;
   secure_vector<uint8_t> msg1raw;
   secure_vector<uint8_t> msg2;
   if(raw.size() > capacity)
      {
      msg1raw = secure_vector<uint8_t> (raw.begin(), raw.begin() + capacity);
      msg2 = secure_vector<uint8_t> (raw.begin() + capacity, raw.end());
      hash->update(msg2);
      }
   else
      {
      msg1raw = raw;
      }
   msg2 = hash->final();

   const uint64_t msg1rawLength = msg1raw.size();
   hash->update_be(msg1rawLength * 8);
   hash->update(msg1raw);
   hash->update(msg2);
   hash->update(salt);
   secure_vector<uint8_t> H3 = hash->final();

   //compute H3(C*||msg1*||H(msg2)||S*) * indicates a recovered value
   const uint64_t msgLength = msg1.size();
   hash->update_be(msgLength * 8);
   hash->update(msg1);
   hash->update(msg2);
   hash->update(salt);
   secure_vector<uint8_t> H2 = hash->final();

   //check if H3 == H2
   bad_input |= CT::Mask<uint8_t>::is_zero(ct_compare_u8(H3.data(), H2.data(), HASH_SIZE));

   CT::unpoison(bad_input);
   return (bad_input.is_set() == false);
   }

}

EMSA* ISO_9796_DS2::clone()
   {
   return new ISO_9796_DS2(m_hash->clone(), m_implicit, m_SALT_SIZE);
   }

/*
 *  ISO-9796-2 signature scheme 2
 *  DS 2 is probabilistic
 */
void ISO_9796_DS2::update(const uint8_t input[], size_t length)
   {
   //need to buffer message completely, before digest
   m_msg_buffer.insert(m_msg_buffer.end(), input, input+length);
   }

/*
 * Return the raw (unencoded) data
 */
secure_vector<uint8_t> ISO_9796_DS2::raw_data()
   {
   secure_vector<uint8_t> retbuffer = m_msg_buffer;
   m_msg_buffer.clear();
   return retbuffer;
   }

/*
 *  ISO-9796-2 scheme 2 encode operation
 */
secure_vector<uint8_t> ISO_9796_DS2::encoding_of(const secure_vector<uint8_t>& msg,
                                                 size_t output_bits,
                                                 RandomNumberGenerator& rng)
   {
   return iso9796_encoding(msg, output_bits, m_hash, m_SALT_SIZE, m_implicit, rng);
   }

/*
 * ISO-9796-2 scheme 2 verify operation
 */
bool ISO_9796_DS2::verify(const secure_vector<uint8_t>& const_coded,
                          const secure_vector<uint8_t>& raw, size_t key_bits)
   {
   return iso9796_verification(const_coded, raw, key_bits, m_hash, m_SALT_SIZE);
   }

/*
 * Return the SCAN name
 */
std::string ISO_9796_DS2::name() const
   {
   return "ISO_9796_DS2(" + m_hash->name() + ","
         + (m_implicit ? "imp" : "exp") + "," + std::to_string(m_SALT_SIZE) + ")";
   }

EMSA* ISO_9796_DS3::clone()
   {
   return new ISO_9796_DS3(m_hash->clone(), m_implicit);
   }

/*
 *  ISO-9796-2 signature scheme 3
 *  DS 3 is deterministic and equals DS2 without salt
 */
void ISO_9796_DS3::update(const uint8_t input[], size_t length)
   {
   //need to buffer message completely, before digest
   m_msg_buffer.insert(m_msg_buffer.end(), input, input+length);
   }

/*
 * Return the raw (unencoded) data
 */
secure_vector<uint8_t> ISO_9796_DS3::raw_data()
   {
   secure_vector<uint8_t> retbuffer = m_msg_buffer;
   m_msg_buffer.clear();
   return retbuffer;
   }

/*
 *  ISO-9796-2 scheme 3 encode operation
 */
secure_vector<uint8_t> ISO_9796_DS3::encoding_of(const secure_vector<uint8_t>& msg,
      size_t output_bits, RandomNumberGenerator& rng)
   {
   return iso9796_encoding(msg, output_bits, m_hash, 0, m_implicit, rng);
   }

/*
 * ISO-9796-2 scheme 3 verify operation
 */
bool ISO_9796_DS3::verify(const secure_vector<uint8_t>& const_coded,
                          const secure_vector<uint8_t>& raw, size_t key_bits)
   {
   return iso9796_verification(const_coded, raw, key_bits, m_hash, 0);
   }
/*
 * Return the SCAN name
 */
std::string ISO_9796_DS3::name() const
   {
   return "ISO_9796_DS3(" + m_hash->name() + "," +
      (m_implicit ? "imp" : "exp") + ")";
   }
}
