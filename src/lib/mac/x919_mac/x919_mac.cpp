/*
* ANSI X9.19 MAC
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mac_utils.h>
#include <botan/x919_mac.h>

namespace Botan {

BOTAN_REGISTER_MAC_NAMED_NOARGS(ANSI_X919_MAC, "X9.19-MAC");

/*
* Update an ANSI X9.19 MAC Calculation
*/
void ANSI_X919_MAC::add_data(const byte input[], size_t length)
   {
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
void ANSI_X919_MAC::final_result(byte mac[])
   {
   if(m_position)
      m_des1->encrypt(m_state);
   m_des2->decrypt(&m_state[0], mac);
   m_des1->encrypt(mac);
   zeroise(m_state);
   m_position = 0;
   }

/*
* ANSI X9.19 MAC Key Schedule
*/
void ANSI_X919_MAC::key_schedule(const byte key[], size_t length)
   {
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
   zeroise(m_state);
   m_position = 0;
   }

std::string ANSI_X919_MAC::name() const
   {
   return "X9.19-MAC";
   }

MessageAuthenticationCode* ANSI_X919_MAC::clone() const
   {
   return new ANSI_X919_MAC;
   }

/*
* ANSI X9.19 MAC Constructor
*/
ANSI_X919_MAC::ANSI_X919_MAC() : m_state(8), m_position(0)
   {
   auto& ciphers = Algo_Registry<BlockCipher>::global_registry();
   m_des1.reset(ciphers.make(BlockCipher::Spec("DES"), ""));
   m_des2.reset(m_des1->clone());
   }

}
