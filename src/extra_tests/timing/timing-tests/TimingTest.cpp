/* 
 * File:   TimingTest.cpp
 * Author: Juraj Somorovsky - juraj.somorovsky@hackmanit.de
 * 
 */

#include "TimingTest.h"
#include <time.h>

TimingTest::TimingTest()
   {
   }

TimingTest::~TimingTest()
   {
   }

void TimingTest::execute_evaluation()
   {
   m_results = std::vector<ticks>(m_measurement_iterations * 2);

   for (int i = 0; i < m_inputs.size() - 1; i++) 
      {
      for (int j = i + 1; j < m_inputs.size(); j++) 
         {
         std::cout << "\nExecuting measurements for inputs " << i << " and " << j;
         std::vector<byte> input1 = prepare_input(m_inputs[i]);
         std::vector<byte> input2 = prepare_input(m_inputs[j]);

         for (int k = 0; k < m_warmup_iterations + m_measurement_iterations; k++) 
            {
            ticks t1 = measure_critical_function(input1);
            ticks t2 = measure_critical_function(input2);

            if (k >= m_warmup_iterations) 
               {
               m_results[ (k - m_warmup_iterations) * 2] = t1;
               m_results[ (k - m_warmup_iterations) * 2 + 1] = t2;
               }
            }
         clock_t t;
         t = clock();
         store_results_in_file(std::to_string(t) + "test" + std::to_string(i) + std::to_string(j));
         }
      }
   }

void TimingTest::store_results_in_file(std::string file)
   {
   std::ofstream output(m_result_folder + "/" + file);
   for (int i = 0; i < m_measurement_iterations; i++) 
      {
      output << 2 * i << ";1;" << m_results[2 * i] << "\n";
      output << 2 * i + 1 << ";2;" << m_results[2 * i + 1] << "\n";
      }
   }

/**
 * Taken from Mona Timing Lib
 * Thanks Sebastian ;)
 * 
 * @return Number of processor ticks read using the RDTSC assembler instruction.
 */
ticks TimingTest::get_ticks()
   {
   ticks ret = 0;
   unsigned long minor = 0;
   unsigned long mayor = 0;

   asm volatile(
                "cpuid \n"
                "rdtsc"
                : "=a"(minor),
                "=d"(mayor)
                : "a" (0)
                : "%ebx", "%ecx"
                );

   ret = ((((ticks) mayor) << 32) | ((ticks) minor));

   return ret;
   }
