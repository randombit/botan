/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_ARGPARSE_H_
#define BOTAN_CLI_ARGPARSE_H_

#include "cli_exceptions.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace Botan_CLI {

class Argument_Parser final {
   public:
      Argument_Parser(const std::string& spec,
                      const std::vector<std::string>& extra_flags = {},
                      const std::vector<std::string>& extra_opts = {});

      void parse_args(const std::vector<std::string>& params);

      bool flag_set(const std::string& flag) const;

      bool has_arg(const std::string& opt_name) const;
      std::string get_arg(const std::string& option) const;

      std::string get_arg_or(const std::string& option, const std::string& otherwise) const;

      size_t get_arg_sz(const std::string& option) const;

      std::vector<std::string> get_arg_list(const std::string& what) const;

      static std::vector<std::string> split_on(const std::string& str, char delim);

   private:
      // set in constructor
      std::vector<std::string> m_spec_args;
      std::set<std::string> m_spec_flags;
      std::map<std::string, std::string> m_spec_opts;
      std::string m_spec_rest;

      // set in parse_args()
      std::map<std::string, std::string> m_user_args;
      std::set<std::string> m_user_flags;
      std::vector<std::string> m_user_rest;
};

std::vector<std::string> Argument_Parser::split_on(const std::string& str, char delim) {
   std::vector<std::string> elems;
   if(str.empty()) {
      return elems;
   }

   std::string substr;
   for(auto i = str.begin(); i != str.end(); ++i) {
      if(*i == delim) {
         if(!substr.empty()) {
            elems.push_back(substr);
         }
         substr.clear();
      } else {
         substr += *i;
      }
   }

   if(substr.empty()) {
      throw CLI_Error("Unable to split string: " + str);
   }
   elems.push_back(substr);

   return elems;
}

bool Argument_Parser::flag_set(const std::string& flag_name) const {
   return m_user_flags.contains(flag_name);
}

bool Argument_Parser::has_arg(const std::string& opt_name) const {
   return m_user_args.contains(opt_name);
}

std::string Argument_Parser::get_arg(const std::string& opt_name) const {
   auto i = m_user_args.find(opt_name);
   if(i == m_user_args.end()) {
      // this shouldn't occur unless you passed the wrong thing to get_arg
      throw CLI_Error("Unknown option " + opt_name + " used (program bug)");
   }
   return i->second;
}

std::string Argument_Parser::get_arg_or(const std::string& opt_name, const std::string& otherwise) const {
   auto i = m_user_args.find(opt_name);
   if(i == m_user_args.end() || i->second.empty()) {
      return otherwise;
   }
   return i->second;
}

size_t Argument_Parser::get_arg_sz(const std::string& opt_name) const {
   const std::string s = get_arg(opt_name);

   try {
      return static_cast<size_t>(std::stoul(s));
   } catch(std::exception&) {
      throw CLI_Usage_Error("Invalid integer value '" + s + "' for option " + opt_name);
   }
}

std::vector<std::string> Argument_Parser::get_arg_list(const std::string& what) const {
   if(what == m_spec_rest) {
      return m_user_rest;
   }

   return split_on(get_arg(what), ',');
}

void Argument_Parser::parse_args(const std::vector<std::string>& params) {
   std::vector<std::string> args;
   for(const auto& param : params) {
      if(param.find("--") == 0) {
         // option
         const auto eq = param.find('=');

         if(eq == std::string::npos) {
            const std::string opt_name = param.substr(2, std::string::npos);

            if(!m_spec_flags.contains(opt_name)) {
               if(m_spec_opts.contains(opt_name)) {
                  throw CLI_Usage_Error("Invalid usage of option --" + opt_name + " without value");
               } else {
                  throw CLI_Usage_Error("Unknown flag --" + opt_name);
               }
            }
            m_user_flags.insert(opt_name);
         } else {
            const std::string opt_name = param.substr(2, eq - 2);
            const std::string opt_val = param.substr(eq + 1, std::string::npos);

            if(!m_spec_opts.contains(opt_name)) {
               throw CLI_Usage_Error("Unknown option --" + opt_name);
            }

            if(m_user_args.contains(opt_name)) {
               throw CLI_Usage_Error("Duplicated option --" + opt_name);
            }

            m_user_args.insert(std::make_pair(opt_name, opt_val));
         }
      } else {
         // argument
         args.push_back(param);
      }
   }

   if(flag_set("help")) {
      return;
   }

   if(args.size() < m_spec_args.size()) {
      // not enough arguments
      throw CLI_Usage_Error("Invalid argument count, got " + std::to_string(args.size()) + " expected " +
                            std::to_string(m_spec_args.size()));
   }

   bool seen_stdin_flag = false;
   size_t arg_i = 0;
   for(const auto& arg : m_spec_args) {
      m_user_args.insert(std::make_pair(arg, args[arg_i]));

      if(args[arg_i] == "-") {
         if(seen_stdin_flag) {
            throw CLI_Usage_Error("Cannot specify '-' (stdin) more than once");
         }
         seen_stdin_flag = true;
      }

      ++arg_i;
   }

   if(m_spec_rest.empty()) {
      if(arg_i != args.size()) {
         throw CLI_Usage_Error("Too many arguments");
      }
   } else {
      m_user_rest.assign(args.begin() + arg_i, args.end());
   }

   // Now insert any defaults for options not supplied by the user
   for(const auto& opt : m_spec_opts) {
      if(!m_user_args.contains(opt.first)) {
         m_user_args.insert(opt);
      }
   }
}

Argument_Parser::Argument_Parser(const std::string& spec,
                                 const std::vector<std::string>& extra_flags,
                                 const std::vector<std::string>& extra_opts) {
   class CLI_Error_Invalid_Spec final : public CLI_Error {
      public:
         explicit CLI_Error_Invalid_Spec(const std::string& bad_spec) :
               CLI_Error("Invalid command spec '" + bad_spec + "'") {}
   };

   const std::vector<std::string> parts = split_on(spec, ' ');

   if(parts.empty()) {
      throw CLI_Error_Invalid_Spec(spec);
   }

   for(size_t i = 1; i != parts.size(); ++i) {
      const auto& s = parts[i];

      if(s.empty()) {
         // ?!? (shouldn't happen)
         throw CLI_Error_Invalid_Spec(spec);
      }

      if(s.size() > 2 && s[0] == '-' && s[1] == '-') {
         // option or flag

         auto eq = s.find('=');

         if(eq == std::string::npos) {
            m_spec_flags.insert(s.substr(2, std::string::npos));
         } else {
            m_spec_opts.insert(std::make_pair(s.substr(2, eq - 2), s.substr(eq + 1, std::string::npos)));
         }
      } else if(s[0] == '*') {
         // rest argument
         if(m_spec_rest.empty() && s.size() > 2) {
            m_spec_rest = s.substr(1, std::string::npos);
         } else {
            throw CLI_Error_Invalid_Spec(spec);
         }
      } else {
         // named argument
         if(!m_spec_rest.empty())  // rest arg wasn't last
         {
            throw CLI_Error_Invalid_Spec(spec);
         }

         m_spec_args.push_back(s);
      }
   }

   for(const std::string& flag : extra_flags) {
      m_spec_flags.insert(flag);
   }
   for(const std::string& opt : extra_opts) {
      m_spec_opts.insert(std::make_pair(opt, ""));
   }
}

}  // namespace Botan_CLI

#endif
