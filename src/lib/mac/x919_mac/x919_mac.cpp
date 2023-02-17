/*
* ANSI X9.19 MAC
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/x919_mac.h>

namespace Botan {

/*
* Update an ANSI X9.19 MAC Calculation
*/
void ANSI_X919_MAC::add_data(const uint8_t input[], size_t length)
   {
   assert_key_material_set();

   size_t xored = std::min(8 - m_position, length);
   xor_buf(&m_state[m_position], input, xored);
   m_position += xored;

   if(m_position < 8) return;

   m_des1->encrypt(m_state);
   input += xored;
   length -= xored;
   while(length >= 8)
      {
      xor_buf(m_state, input, 8);
      m_des1->encrypt(m_state);
      input += 8;
      length -= 8;
      }

   xor_buf(m_state, input, length);
   m_position = length;
   }

/*
* Finalize an ANSI X9.19 MAC Calculation
*/
void ANSI_X919_MAC::final_result(uint8_t mac[])
   {
   if(m_position)
      m_des1->encrypt(m_state);
   m_des2->decrypt(m_state.data(), mac);
   m_des1->encrypt(mac);
   zeroise(m_state);
   m_position = 0;
   }

bool ANSI_X919_MAC::has_keying_material() const
   {
   return m_des1->has_keying_material() &&
      m_des2->has_keying_material();
   }

/*
* ANSI X9.19 MAC Key Schedule
*/
void ANSI_X919_MAC::key_schedule(const uint8_t key[], size_t length)
   {
   m_state.resize(8);

   m_des1->set_key(key, 8);

   if(length == 16)
      key += 8;

   m_des2->set_key(key, 8);
   }

/*
* Clear memory of sensitive data
*/
void ANSI_X919_MAC::clear()
   {
   m_des1->clear();
   m_des2->clear();
   zap(m_state);
   m_position = 0;
   }

std::string ANSI_X919_MAC::name() const
   {
   return "X9.19-MAC";
   }

std::unique_ptr<MessageAuthenticationCode> ANSI_X919_MAC::new_object() const
   {
   return std::make_unique<ANSI_X919_MAC>();
   }

/*
* ANSI X9.19 MAC Constructor
*/
ANSI_X919_MAC::ANSI_X919_MAC() :
   m_des1(BlockCipher::create("DES")),
   m_des2(m_des1->new_object()),
   m_position(0)
   {
   }

}
