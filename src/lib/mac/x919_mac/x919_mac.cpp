/*
* ANSI X9.19 MAC
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/x919_mac.h>

#include <botan/internal/stl_util.h>

namespace Botan {

/*
* Update an ANSI X9.19 MAC Calculation
*/
void ANSI_X919_MAC::add_data(std::span<const uint8_t> input) {
   assert_key_material_set();

   BufferSlicer in(input);

   const auto to_be_xored = in.take(std::min(8 - m_position, in.remaining()));
   xor_buf(&m_state[m_position], to_be_xored.data(), to_be_xored.size());
   m_position += to_be_xored.size();

   if(m_position < 8) {
      return;
   }

   m_des1->encrypt(m_state);
   while(in.remaining() >= 8) {
      xor_buf(m_state, in.take(8).data(), 8);
      m_des1->encrypt(m_state);
   }

   const auto remaining = in.take(in.remaining());
   xor_buf(m_state, remaining.data(), remaining.size());
   m_position = remaining.size();
}

/*
* Finalize an ANSI X9.19 MAC Calculation
*/
void ANSI_X919_MAC::final_result(std::span<uint8_t> mac) {
   if(m_position) {
      m_des1->encrypt(m_state);
   }
   m_des2->decrypt(m_state.data(), mac.data());
   m_des1->encrypt(mac.data());
   zeroise(m_state);
   m_position = 0;
}

bool ANSI_X919_MAC::has_keying_material() const {
   return m_des1->has_keying_material() && m_des2->has_keying_material();
}

/*
* ANSI X9.19 MAC Key Schedule
*/
void ANSI_X919_MAC::key_schedule(std::span<const uint8_t> key) {
   m_state.resize(8);

   m_des1->set_key(key.first(8));

   if(key.size() == 16) {
      key = key.last(8);
   }

   m_des2->set_key(key.first(8));
}

/*
* Clear memory of sensitive data
*/
void ANSI_X919_MAC::clear() {
   m_des1->clear();
   m_des2->clear();
   zap(m_state);
   m_position = 0;
}

std::string ANSI_X919_MAC::name() const {
   return "X9.19-MAC";
}

std::unique_ptr<MessageAuthenticationCode> ANSI_X919_MAC::new_object() const {
   return std::make_unique<ANSI_X919_MAC>();
}

/*
* ANSI X9.19 MAC Constructor
*/
ANSI_X919_MAC::ANSI_X919_MAC() : m_des1(BlockCipher::create("DES")), m_des2(m_des1->new_object()), m_position(0) {}

}  // namespace Botan
