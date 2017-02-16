/* 
 * File:   ecdsa.cpp
 *
 * 
 */

#include "TimingTest.h"

ECDSATest::ECDSATest(std::vector<std::string> &inputs, std::string result_folder, std::string ecgroup) :
   m_privkey(system_rng(), Botan::EC_Group(ecgroup)),
        m_order(m_privkey.domain().get_order()),
        m_base_point(m_privkey.domain().get_base_point(), m_order),
        m_x(m_privkey.private_value()),
        m_mod_order(m_order)
   {
   m_inputs = inputs;
   m_result_folder = result_folder;
   }

std::vector<byte> ECDSATest::prepare_input(std::string input)
   {
   const std::vector<byte> input_vector = Botan::hex_decode(input);
   return input_vector;
   }

ticks ECDSATest::measure_critical_function(std::vector<byte> input)
   {
   const BigInt k(input.data(), input.size());
   const BigInt msg(system_rng(), m_order.bits());
   
   ticks start = this->get_ticks();
   
   //The following ECDSA operations involve and should not leak any information about k.
   const Botan::PointGFp k_times_P = m_base_point.blinded_multiply(k, system_rng());
   const BigInt r = m_mod_order.reduce(k_times_P.get_affine_x());
   const BigInt s = m_mod_order.multiply(inverse_mod(k, m_order), mul_add(m_x, r, msg));
   
   ticks end = get_ticks();

   return (end - start);
   }
