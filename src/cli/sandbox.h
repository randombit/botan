/*
* (C) 2019 David Carlier <devnexen@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_SANDBOX_H_
#define BOTAN_CLI_SANDBOX_H_

#include <string>

namespace Botan_CLI {

class Sandbox {
   public:
      explicit Sandbox();
      virtual ~Sandbox();

      static bool init();

      const std::string& name() const { return m_name; }

   private:
      std::string m_name;
};
}  // namespace Botan_CLI

#endif
