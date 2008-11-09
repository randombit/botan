/**
SCAN Name Abstraction
(C) 2008 Jack Lloyd
*/

#ifndef BOTAN_SCAN_NAME_H__
#define BOTAN_SCAN_NAME_H__

#include <botan/types.h>
#include <string>
#include <vector>

namespace Botan {

/**
A class encapsulating a SCAN name (similar to JCE conventions)
http://www.users.zetnet.co.uk/hopwood/crypto/scan/
*/
class SCAN_Name
   {
   public:
      /**
      @param algo_spec A SCAN name
      */
      SCAN_Name(const std::string& algo_spec);

      /**
      @return the algorithm name
      */
      std::string algo_name() const { return name[0]; }

      /**
      @return the number of arguments
      */
      u32bit arg_count() const { return name.size() - 1; }

      /**
      @param i which argument
      @return the ith argument
      */
      std::string argument(u32bit i);

      /**
      @param i which argument
      @return the ith argument as a u32bit, or a default value
      */
      u32bit argument_as_u32bit(u32bit i, u32bit def_value);

   private:
      std::vector<std::string> name;
   };

}

#endif
