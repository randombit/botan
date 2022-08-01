/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_XML_REPORTER_H_
#define BOTAN_TEST_XML_REPORTER_H_

#include "tests.h"

namespace Botan_Tests {

class XmlReporter
   {
   public:
   	  XmlReporter(std::string output_dir) : m_output_dir(std::move(output_dir)) {}
   	  ~XmlReporter() = default;
   	  XmlReporter(const XmlReporter&) = delete;
   	  XmlReporter& operator=(const XmlReporter&) = delete;
   	  XmlReporter(XmlReporter&&) = default;
   	  XmlReporter& operator=(XmlReporter&&) = default;

   	  void record(const std::string& name, const std::vector<const Test::Result*>& results);

   private:
   	  std::string m_output_dir;
   };

}

#endif
