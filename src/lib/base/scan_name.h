/*
* SCAN Name Abstraction
* (C) 2008,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SCAN_NAME_H__
#define BOTAN_SCAN_NAME_H__

#include <botan/types.h>
#include <string>
#include <vector>
#include <mutex>
#include <map>

namespace Botan {

/**
A class encapsulating a SCAN name (similar to JCE conventions)
http://www.users.zetnet.co.uk/hopwood/crypto/scan/
*/
class BOTAN_DLL SCAN_Name
   {
   public:
      /**
      * @param algo_spec A SCAN-format name
      */
      explicit SCAN_Name(const char* algo_spec);

      /**
      * @param algo_spec A SCAN-format name
      */
      explicit SCAN_Name(std::string algo_spec);

      /**
      * @param algo_spec A SCAN-format name
      */
      SCAN_Name(std::string algo_spec, const std::string& extra);

      /**
      * @return original input string
      */
      const std::string& as_string() const { return m_orig_algo_spec; }

      /**
      * @return algorithm name
      */
      const std::string& algo_name() const { return m_alg_name; }

      /**
      * @return algorithm name plus any arguments
      */
      std::string algo_name_and_args() const { return algo_name() + all_arguments(); }

      /**
      * @return all arguments
      */
      std::string all_arguments() const;

      /**
      * @return number of arguments
      */
      size_t arg_count() const { return m_args.size(); }

      /**
      * @param lower is the lower bound
      * @param upper is the upper bound
      * @return if the number of arguments is between lower and upper
      */
      bool arg_count_between(size_t lower, size_t upper) const
         { return ((arg_count() >= lower) && (arg_count() <= upper)); }

      /**
      * @param i which argument
      * @return ith argument
      */
      std::string arg(size_t i) const;

      /**
      * @param i which argument
      * @param def_value the default value
      * @return ith argument or the default value
      */
      std::string arg(size_t i, const std::string& def_value) const;

      /**
      * @param i which argument
      * @param def_value the default value
      * @return ith argument as an integer, or the default value
      */
      size_t arg_as_integer(size_t i, size_t def_value) const;

      /**
      * @return cipher mode (if any)
      */
      std::string cipher_mode() const
         { return (m_mode_info.size() >= 1) ? m_mode_info[0] : ""; }

      /**
      * @return cipher mode padding (if any)
      */
      std::string cipher_mode_pad() const
         { return (m_mode_info.size() >= 2) ? m_mode_info[1] : ""; }

      static void add_alias(const std::string& alias, const std::string& basename);

      static std::string deref_alias(const std::string& alias);
   private:
      static std::mutex g_alias_map_mutex;
      static std::map<std::string, std::string> g_alias_map;

      std::string m_orig_algo_spec;
      std::string m_alg_name;
      std::vector<std::string> m_args;
      std::vector<std::string> m_mode_info;
   };

}

#endif
