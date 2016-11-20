/* 
 * File:   BleichenbacherTest.cpp
 * Author: Juraj Somorovsky - juraj.somorovsky@hackmanit.de
 * 
 */

#include "TimingTest.h"

BleichenbacherTest::BleichenbacherTest(std::vector<std::string> &inputs,
        std::string result_folder, int keysize) : 
   m_privkey(system_rng(), keysize), 
   m_pubkey(m_privkey), 
   m_enc(m_pubkey, m_encrypt_padding), 
   m_dec(m_privkey, m_decrypt_padding) 
   {
   m_inputs = inputs;
   m_result_folder = result_folder;
   }

std::vector<byte> BleichenbacherTest::prepare_input(std::string input)
   {
   const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
   const std::vector<byte> encrypted = m_enc.encrypt(input_vector, system_rng());
   return encrypted;
   }

ticks BleichenbacherTest::measure_critical_function(std::vector<byte> input)
   {
   const Botan::byte* in = &input[0];

   ticks start = this->get_ticks();
   m_dec.decrypt_or_random(in, m_ctext_length, m_expected_content_size, system_rng());
   ticks end = get_ticks();

   return (end - start);
   }
