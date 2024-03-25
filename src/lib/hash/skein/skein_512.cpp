/*
* The Skein-512 hash function
* (C) 2009,2010,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/skein_512.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <algorithm>

namespace Botan {

Skein_512::Skein_512(size_t arg_output_bits, std::string_view arg_personalization) :
      m_personalization(arg_personalization),
      m_output_bits(arg_output_bits),
      m_threefish(std::make_unique<Threefish_512>()),
      m_T(2) {
   if(m_output_bits == 0 || m_output_bits % 8 != 0 || m_output_bits > 512) {
      throw Invalid_Argument("Bad output bits size for Skein-512");
   }

   initial_block();
}

std::string Skein_512::name() const {
   if(m_personalization.empty()) {
      return fmt("Skein-512({})", m_output_bits);
   } else {
      return fmt("Skein-512({},{})", m_output_bits, m_personalization);
   }
}

std::unique_ptr<HashFunction> Skein_512::new_object() const {
   return std::make_unique<Skein_512>(m_output_bits, m_personalization);
}

std::unique_ptr<HashFunction> Skein_512::copy_state() const {
   auto copy = std::make_unique<Skein_512>(m_output_bits, m_personalization);
   copy->m_threefish->m_K = this->m_threefish->m_K;
   copy->m_T = this->m_T;
   copy->m_buffer = this->m_buffer;
   return copy;
}

void Skein_512::clear() {
   m_buffer.clear();

   initial_block();
}

void Skein_512::reset_tweak(type_code type, bool is_final) {
   m_T[0] = 0;

   m_T[1] =
      (static_cast<uint64_t>(type) << 56) | (static_cast<uint64_t>(1) << 62) | (static_cast<uint64_t>(is_final) << 63);
}

void Skein_512::initial_block() {
   const uint8_t zeros[64] = {0};

   m_threefish->set_key(zeros, sizeof(zeros));

   // ASCII("SHA3") followed by version (0x0001) code
   uint8_t config_str[32] = {0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0};
   store_le(uint32_t(m_output_bits), config_str + 8);

   reset_tweak(SKEIN_CONFIG, true);
   ubi_512(config_str, sizeof(config_str));

   if(!m_personalization.empty()) {
      /*
        This is a limitation of this implementation, and not of the
        algorithm specification. Could be fixed relatively easily, but
        doesn't seem worth the trouble.
      */
      if(m_personalization.length() > 64) {
         throw Invalid_Argument("Skein personalization must be less than 64 bytes");
      }

      const uint8_t* bits = cast_char_ptr_to_uint8(m_personalization.data());
      reset_tweak(SKEIN_PERSONALIZATION, true);
      ubi_512(bits, m_personalization.length());
   }

   reset_tweak(SKEIN_MSG, false);
}

void Skein_512::ubi_512(const uint8_t msg[], size_t msg_len) {
   secure_vector<uint64_t> M(8);

   do {
      const size_t to_proc = std::min<size_t>(msg_len, 64);
      m_T[0] += to_proc;

      load_le(M.data(), msg, to_proc / 8);

      if(to_proc % 8) {
         for(size_t j = 0; j != to_proc % 8; ++j) {
            M[to_proc / 8] |= static_cast<uint64_t>(msg[8 * (to_proc / 8) + j]) << (8 * j);
         }
      }

      m_threefish->skein_feedfwd(M, m_T);

      // clear first flag if set
      m_T[1] &= ~(static_cast<uint64_t>(1) << 62);

      msg_len -= to_proc;
      msg += to_proc;
   } while(msg_len);
}

void Skein_512::add_data(std::span<const uint8_t> input) {
   BufferSlicer in(input);

   while(!in.empty()) {
      if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
         ubi_512(one_block->data(), one_block->size());
      }

      if(m_buffer.in_alignment()) {
         const auto [aligned_data, full_blocks] = m_buffer.aligned_data_to_process(in);
         if(full_blocks > 0) {
            ubi_512(aligned_data.data(), aligned_data.size());
         }
      }
   }
}

void Skein_512::final_result(std::span<uint8_t> out) {
   m_T[1] |= (static_cast<uint64_t>(1) << 63);  // final block flag

   const auto pos = m_buffer.elements_in_buffer();
   m_buffer.fill_up_with_zeros();
   ubi_512(m_buffer.consume().data(), pos);

   const uint8_t counter[8] = {0};

   reset_tweak(SKEIN_OUTPUT, true);
   ubi_512(counter, sizeof(counter));

   copy_out_le(out.first(m_output_bits / 8), m_threefish->m_K);

   initial_block();
}

}  // namespace Botan
