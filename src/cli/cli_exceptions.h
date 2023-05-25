/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_EXCEPTIONS_H_
#define BOTAN_CLI_EXCEPTIONS_H_

#include <stdexcept>
#include <string>

namespace Botan_CLI {

class CLI_Error : public std::runtime_error {
   public:
      explicit CLI_Error(const std::string& s) : std::runtime_error(s) {}
};

class CLI_IO_Error final : public CLI_Error {
   public:
      CLI_IO_Error(const std::string& op, const std::string& who) : CLI_Error("Error " + op + " " + who) {}
};

class CLI_Usage_Error final : public CLI_Error {
   public:
      explicit CLI_Usage_Error(const std::string& what) : CLI_Error(what) {}
};

/* Thrown eg when a requested feature was compiled out of the library
   or is not available, eg hashing with MD2
*/
class CLI_Error_Unsupported final : public CLI_Error {
   public:
      CLI_Error_Unsupported(const std::string& msg) : CLI_Error(msg) {}

      CLI_Error_Unsupported(const std::string& what, const std::string& who) :
            CLI_Error(what + " with '" + who + "' unsupported or not available") {}
};

}  // namespace Botan_CLI

#endif
