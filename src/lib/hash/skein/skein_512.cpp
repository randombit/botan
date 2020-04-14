/*
* The Skein-512 hash function
* (C) 2009,2010,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/skein_512.h>
#include <botan/loadstor.h>
#include <botan/exceptn.h>
#include <algorithm>


namespace Botan {

Skein_512::Skein_512(size_t arg_output_bits,
                     const std::string& arg_personalization) :
   m_personalization(arg_personalization),
   m_output_bits(arg_output_bits),
   m_threefish(new Threefish_512),
   m_T(2), m_buffer(64), m_buf_pos(0), m_macKey(0)
   {
   if(m_output_bits == 0 || m_output_bits % 8 != 0)
      throw Invalid_Argument("Bad output bits size for Skein-512");

   initial_block();
   }

std::string Skein_512::name() const
   {
   if(!m_personalization.empty())
      return "Skein-512(" + std::to_string(m_output_bits) + "," +
                            m_personalization + ")";
   return "Skein-512(" + std::to_string(m_output_bits) + ")";
   }

HashFunction* Skein_512::clone() const
   {
   return new Skein_512(m_output_bits, m_personalization);
   }

std::unique_ptr<HashFunction> Skein_512::copy_state() const
   {
   std::unique_ptr<Skein_512> copy(new Skein_512(m_output_bits, m_personalization));

   copy->m_threefish->m_K = this->m_threefish->m_K;
   copy->m_T = this->m_T;
   copy->m_buffer = this->m_buffer;
   copy->m_buf_pos = this->m_buf_pos;

   // work around GCC 4.8 bug
   return std::unique_ptr<HashFunction>(copy.release());
   }

void Skein_512::clear()
   {
   zeroise(m_buffer);
   m_buf_pos = 0;

   initial_block();
   }

void Skein_512::reset_tweak(type_code type, bool is_final)
   {
   m_T[0] = 0;

   m_T[1] = (static_cast<uint64_t>(type) << 56U) |
            (static_cast<uint64_t>(1) << 62U) |
            (static_cast<uint64_t>(is_final) << 63U);
   }

void Skein_512::initial_block()
   {
   const uint8_t zeros[64] = { 0 };

   m_threefish->set_key(zeros, sizeof(zeros));


   // When a MAC key is present compute a hash from key data as follows:
   // - Threefish key (aka chaining variable) already set to empty key above - OK
   // - The key may be of any length >= 1
   // - compute hash without Skein OUTPUT stage
   // - set the hashed key as new threefish key, then continue as usual
   if (!m_macKey.empty()) {
       uint8_t hashedKey[64] = { 0 };

       reset_tweak(SKEIN_KEY, false);
       add_data(m_macKey.data(), m_macKey.size());
       final_result_pad(hashedKey);
       m_threefish->set_key(hashedKey, sizeof(hashedKey));
   }

   // ASCII("SHA3") followed by version (0x0001) code
   uint8_t config_str[32] = { 0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0 };
   store_le(uint32_t(m_output_bits), config_str + 8);

   reset_tweak(SKEIN_CONFIG, true);
   ubi_512(config_str, sizeof(config_str));

   if (!m_personalization.empty()) {
       const uint8_t* bits = cast_char_ptr_to_uint8(m_personalization.data());
       uint8_t dummyOut[64] = { 0 };

       reset_tweak(SKEIN_PERSONALIZATION, true);

       // add_data, final_result_pad: these call skein_feedfwd one or more times to process
       // the full length of personalization data to setup chain variables
       add_data(bits, m_personalization.length());
       final_result_pad(dummyOut);      // Don't need the output, discard it
   }

   reset_tweak(SKEIN_MSG, false);
   }

void Skein_512::ubi_512(const uint8_t msg[], size_t msg_len)
   {
   secure_vector<uint64_t> M(8);

   do
      {
      const size_t to_proc = std::min<size_t>(msg_len, 64);
      m_T[0] += to_proc;

      load_le(M.data(), msg, to_proc / 8);

      if(to_proc % 8)
         {
         for(size_t j = 0; j != to_proc % 8; ++j)
           M[to_proc/8] |= static_cast<uint64_t>(msg[8*(to_proc/8)+j]) << (8*j);
         }

      m_threefish->skein_feedfwd(M, m_T);

      // clear first flag if set
      m_T[1] &= ~(static_cast<uint64_t>(1) << 62U);

      msg_len -= to_proc;
      msg += to_proc;
      } while(msg_len);
   }

void Skein_512::add_data(const uint8_t input[], size_t length)
   {
   if(length == 0)
      return;

   if(m_buf_pos)
      {
      buffer_insert(m_buffer, m_buf_pos, input, length);
      if(m_buf_pos + length > 64)
         {
         ubi_512(m_buffer.data(), m_buffer.size());

         input += (64 - m_buf_pos);
         length -= (64 - m_buf_pos);
         m_buf_pos = 0;
         }
      }

   const size_t full_blocks = (length - 1) / 64;

   if(full_blocks)
      ubi_512(input, 64*full_blocks);

   length -= full_blocks * 64;

   buffer_insert(m_buffer, m_buf_pos, input + full_blocks * 64, length);
   m_buf_pos += length;
   }

#define FLAG_BIT_PAD   (((uint64_t)  1 ) << 55U)

void Skein_512::add_data_bits(const uint8_t input[], size_t lengthInBits) {
    if ((m_T[1] & FLAG_BIT_PAD) != 0) {
        throw Invalid_Argument("Only last update/add data is allowed to have partial byte.");
    }

    // Check for partial byte length
    if ((lengthInBits & 0x7U) == 0) {
        return add_data(input, lengthInBits >> 3U);
    }
    // fill the buffer first, including the last partial byte, only then modify the buffer
    add_data(input, (lengthInBits >> 3U) + 1);

    m_T[1] |= FLAG_BIT_PAD;

    // now "pad" the final partial byte the way NIST likes
    // internal sanity check: there IS a partial byte in the buffer!
    if (m_buf_pos == 0) {
        throw Invalid_Argument("Wrong length detected while hashing partial byte (bit stream).");
    }
    auto mask = (1U << (7 - (lengthInBits & 0x7U)));             // partial byte bit mask
    m_buffer[m_buf_pos-1] = (m_buffer[m_buf_pos-1] & (0U - mask)) | mask;    //apply bit padding on final byte (in the buffer)
}

void Skein_512::final_result(uint8_t out[])
{
    m_T[1] |= (static_cast<uint64_t>(1) << 63U); // final block flag

    for(size_t i = m_buf_pos; i != m_buffer.size(); ++i)
        m_buffer[i] = 0;

    ubi_512(m_buffer.data(), m_buf_pos);

    uint8_t counter[8] = { 0 };
    uint64_t counter64[1] = { 0 };

    size_t byteCnt = (m_output_bits + 7) >> 3U;             // total number of output bytes
    size_t n = 0;

    // run Threefish in "counter mode" to generate output
    m_threefish->save_key_data();                           // save current counter mode "key"
    for (uint64_t i = 0; i * 64 < byteCnt; i++) {
        load_le(counter64, reinterpret_cast<uint8_t *>(&i), 1);
        reset_tweak(SKEIN_OUTPUT, true);
        store_le(counter64[0], counter);
        ubi_512(counter, sizeof(counter));                  // Do 'counter' encryption
        n = byteCnt - i * 64;                               // number of output bytes left to go
        if (n >= 64) {
            n = 64;
        }
        copy_out_vec_le(out + i * 64, n, m_threefish->m_K);

        m_threefish->restore_key_data();   /* restore the counter mode key for next time */
    }
    m_buf_pos = 0;
    initial_block();
}

    void Skein_512::final_result_pad(uint8_t out[])
    {
        m_T[1] |= (static_cast<uint64_t>(1) << 63U); // final block flag

        for(size_t i = m_buf_pos; i != m_buffer.size(); ++i)
            m_buffer[i] = 0;

        ubi_512(m_buffer.data(), m_buf_pos);
        copy_out_vec_le(out, 512/8, m_threefish->m_K);

        m_buf_pos = 0;
    }

    void Skein_512::setMacKey(const uint8_t key[], size_t key_len)
    {
        m_macKey = secure_vector<u_int8_t > (key, key+key_len);
        initial_block();
    }
}
