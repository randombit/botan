/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_XML_REPORTER_H_
#define BOTAN_TEST_XML_REPORTER_H_

#include "../tests.h"

#include <memory>

namespace Botan_Tests {

class XmlReporterInternal;

class XmlReporter
   {
   public:
      XmlReporter(std::string output_dir);
      ~XmlReporter();
      XmlReporter(const XmlReporter&) = delete;
      XmlReporter& operator=(const XmlReporter&) = delete;
      XmlReporter(XmlReporter&&) = default;
      XmlReporter& operator=(XmlReporter&&) = default;

      void record(const std::string& name, const Test::Result& result);
      void render(std::ostream& output_stream) const;

   private:
      size_t tests() const;
      size_t passed() const;
      size_t failed() const;
      std::chrono::nanoseconds elapsed_time() const;

   private:
      std::string m_output_dir;
      std::unique_ptr<XmlReporterInternal> m_internal;
   };

}

#endif
