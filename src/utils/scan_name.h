/**
SCAN Name Abstraction
(C) 2008 Jack Lloyd
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
      @param providers An optional list of providers (like "sse2,openssl,x86-64,core")
      */
      SCAN_Name(const std::string& algo_spec,
                const std::string& providers = "");

      /**
      @return the algorithm name
      */
      std::string algo_name() const { return name[0]; }

      /**
      @return the number of arguments
      */
      u32bit arg_count() const { return name.size() - 1; }

      /**
      @param provider a provider name
      @returns if this provider was allowed by the request
      */
      bool provider_allowed(const std::string& provider) const;

      /**
      @return if the number of arguments is between lower and upper
      */
      bool arg_count_between(u32bit lower, u32bit upper)
         { return ((arg_count() >= lower) && (arg_count() <= upper)); }

      /**
      @param i which argument
      @return the ith argument
      */
      std::string argument(u32bit i) const;

      /**
      @param i which argument
      @return the ith argument as a u32bit, or a default value
      */
      u32bit argument_as_u32bit(u32bit i, u32bit def_value) const;

      std::string as_string() const { return orig_algo_spec; }
      std::string providers_string() const { return orig_providers; }
   private:
      std::string orig_algo_spec, orig_providers;
      std::vector<std::string> name;
      std::set<std::string> providers;
   };

}

#endif
