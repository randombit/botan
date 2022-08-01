/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_xml_reporter.h"

#include <iostream>

namespace Botan_Tests {

void XmlReporter::record(const std::string& name, const std::vector<const Test::Result*>& results)
   {
   std::cout << "testsuite: " << name << std::endl;
   for (const auto result : results)
      {
      std::cout << "<testcase name=\"" << result->who() << "\" checks=\"" << result->tests_run() << "\"";

      const auto& failures = result->failures();
      const auto& notes = result->notes();

      if(failures.size() + notes.size() == 0)
         {
         std::cout << " />" << std::endl;
         }
      else
         {
         std::cout << ">" << std::endl;

         for (const auto& note : notes)
            {
            std::cout << "<error type=\"info\"><![CDATA[" << note << "]]></error>" << std::endl;
            }
         for (const auto& fail : failures)
            {
            std::cout << "<failure type=\"error\"><![CDATA[" << fail << "]]></error>" << std::endl;
            }

         std::cout << "</testcase>" << std::endl;
         }
      }
   }

}
