/**
SCAN Name Abstraction
(C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SCAN_NAME_H__
#define BOTAN_SCAN_NAME_H__

#include <botan/types.h>
#include <string>
#include <vector>
#include <set>

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
      @return the original input string
      */
      std::string as_string() const { return orig_algo_spec; }

      /**
      @return the algorithm name
      */
      std::string algo_name() const { return name[0]; }

      /**
      @return the number of arguments
      */
      u32bit arg_count() const { return name.size() - 1; }

      /**
      @return if the number of arguments is between lower and upper
      */
      bool arg_count_between(u32bit lower, u32bit upper) const
         { return ((arg_count() >= lower) && (arg_count() <= upper)); }

      /**
      @param i which argument
      @return the ith argument
      */
      std::string arg(u32bit i) const;

      /**
      @param i which argument
      @param def_value the default value
      @return the ith argument or the default value
      */
      std::string arg(u32bit i, const std::string& def_value) const;

      /**
      @param i which argument
      @param def_value the default value
      @return the ith argument as a u32bit, or the default value
      */
      u32bit arg_as_u32bit(u32bit i, u32bit def_value) const;
   private:
      std::string orig_algo_spec;
      std::vector<std::string> name;
   };

}

#endif
