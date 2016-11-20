/* 
 * File:   Lucky13Test.cpp
 * Author: Juraj Somorovsky - juraj.somorovsky@hackmanit.de
 * 
 */

#include "TimingTest.h"

Lucky13Test::Lucky13Test(std::vector<std::string> &inputs, std::string result_folder,
        const std::string& mac_name, size_t mac_keylen) :
   m_dec("AES-128", 16, mac_name, mac_keylen, true, false),
   m_mac_keylen (mac_keylen) 
   {
   m_inputs = inputs;
   m_result_folder = result_folder;
   }

std::vector<byte> Lucky13Test::prepare_input(std::string input)
   {
   const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
   const std::vector<uint8_t> key(16);
   const std::vector<uint8_t> iv(16);
    
   std::unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode("AES-128/CBC/NoPadding", Botan::ENCRYPTION));
   enc->set_key(key);
   enc->start(iv);
   Botan::secure_vector<uint8_t> buf(input_vector.begin(), input_vector.end());
   enc->finish(buf);

   return unlock(buf);
   }

ticks Lucky13Test::measure_critical_function(std::vector<byte> input)
   {
   Botan::secure_vector<byte> data(input.begin(), input.end());
   Botan::secure_vector<byte> aad(13);
   const Botan::secure_vector<byte> iv(16);
   Botan::secure_vector<byte> key(16 + m_mac_keylen);

   m_dec.set_key(unlock(key));
   m_dec.set_ad(unlock(aad));
   m_dec.start(unlock(iv));

   ticks start = this->get_ticks();
   try 
      {
      m_dec.finish(data);
      } 
      catch (Botan::TLS::TLS_Exception e) 
      {

      }
   ticks end = get_ticks();
   return (end - start);
   }
