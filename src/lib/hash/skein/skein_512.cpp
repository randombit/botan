/*
* The Skein-512 hash function
* (C) 2009,2010,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_utils.h>
#include <botan/skein_512.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

BOTAN_REGISTER_NAMED_T(HashFunction, "Skein-512", Skein_512, Skein_512::make);

Skein_512* Skein_512::make(const Spec& spec)
   {
   return new Skein_512(spec.arg_as_integer(0, 512), spec.arg(1, ""));
   }

Skein_512::Skein_512(size_t arg_output_bits,
                     const std::string& arg_personalization) :
   personalization(arg_personalization),
   output_bits(arg_output_bits),
   m_threefish(new Threefish_512),
   T(2), buffer(64), buf_pos(0)
   {
   if(output_bits == 0 || output_bits % 8 != 0 || output_bits > 512)
      throw Invalid_Argument("Bad output bits size for Skein-512");

   initial_block();
   }

std::string Skein_512::name() const
   {
   if(personalization != "")
      return "Skein-512(" + std::to_string(output_bits) + "," +
                            personalization + ")";
   return "Skein-512(" + std::to_string(output_bits) + ")";
   }

HashFunction* Skein_512::clone() const
   {
   return new Skein_512(output_bits, personalization);
   }

void Skein_512::clear()
   {
   zeroise(buffer);
   buf_pos = 0;

   initial_block();
   }

void Skein_512::reset_tweak(type_code type, bool final)
   {
   T[0] = 0;

   T[1] = (static_cast<u64bit>(type) << 56) |
          (static_cast<u64bit>(1) << 62) |
          (static_cast<u64bit>(final) << 63);
   }

void Skein_512::initial_block()
   {
   const byte zeros[64] = { 0 };

   m_threefish->set_key(zeros, sizeof(zeros));

   // ASCII("SHA3") followed by version (0x0001) code
   byte config_str[32] = { 0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0 };
   store_le(u32bit(output_bits), config_str + 8);

   reset_tweak(SKEIN_CONFIG, true);
   ubi_512(config_str, sizeof(config_str));

   if(personalization != "")
      {
      /*
        This is a limitation of this implementation, and not of the
        algorithm specification. Could be fixed relatively easily, but
        doesn't seem worth the trouble.
      */
      if(personalization.length() > 64)
         throw Invalid_Argument("Skein personalization must be less than 64 bytes");

      const byte* bits = reinterpret_cast<const byte*>(personalization.data());
      reset_tweak(SKEIN_PERSONALIZATION, true);
      ubi_512(bits, personalization.length());
      }

   reset_tweak(SKEIN_MSG, false);
   }

void Skein_512::ubi_512(const byte msg[], size_t msg_len)
   {
   secure_vector<u64bit> M(8);

   do
      {
      const size_t to_proc = std::min<size_t>(msg_len, 64);
      T[0] += to_proc;

      load_le(&M[0], msg, to_proc / 8);

      if(to_proc % 8)
         {
         for(size_t j = 0; j != to_proc % 8; ++j)
           M[to_proc/8] |= static_cast<u64bit>(msg[8*(to_proc/8)+j]) << (8*j);
         }

      m_threefish->skein_feedfwd(M, T);

      // clear first flag if set
      T[1] &= ~(static_cast<u64bit>(1) << 62);

      msg_len -= to_proc;
      msg += to_proc;
      } while(msg_len);
   }

void Skein_512::add_data(const byte input[], size_t length)
   {
   if(length == 0)
      return;

   if(buf_pos)
      {
      buffer_insert(buffer, buf_pos, input, length);
      if(buf_pos + length > 64)
         {
         ubi_512(&buffer[0], buffer.size());

         input += (64 - buf_pos);
         length -= (64 - buf_pos);
         buf_pos = 0;
         }
      }

   const size_t full_blocks = (length - 1) / 64;

   if(full_blocks)
      ubi_512(input, 64*full_blocks);

   length -= full_blocks * 64;

   buffer_insert(buffer, buf_pos, input + full_blocks * 64, length);
   buf_pos += length;
   }

void Skein_512::final_result(byte out[])
   {
   T[1] |= (static_cast<u64bit>(1) << 63); // final block flag

   for(size_t i = buf_pos; i != buffer.size(); ++i)
      buffer[i] = 0;

   ubi_512(&buffer[0], buf_pos);

   const byte counter[8] = { 0 };

   reset_tweak(SKEIN_OUTPUT, true);
   ubi_512(counter, sizeof(counter));

   copy_out_vec_le(out, output_bits / 8, m_threefish->m_K);

   buf_pos = 0;
   initial_block();
   }

}
