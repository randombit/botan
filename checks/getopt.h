
#ifndef BOTAN_CHECK_GETOPT_H__
#define BOTAN_CHECK_GETOPT_H__

#include <string>
#include <vector>
#include <map>

class OptionParser
   {
   public:
      std::vector<std::string> leftovers() const { return leftover; }
      bool is_set(const std::string&) const;

      std::string value(const std::string&) const;
      std::string value_if_set(const std::string&) const;

      void parse(char*[]);
      OptionParser(const std::string&);
   private:
      class OptionFlag
         {
         public:
            std::string name() const { return opt_name; }
            bool takes_arg() const { return opt_takes_arg; }

            OptionFlag(const std::string& opt_string)
               {
               std::string::size_type mark = opt_string.find('=');
               opt_name = opt_string.substr(0, mark);
               opt_takes_arg = (mark != std::string::npos);
               }
         private:
            std::string opt_name;
            bool opt_takes_arg;
         };

      OptionFlag find_option(const std::string&) const;

      std::vector<OptionFlag> flags;
      std::map<std::string, std::string> options;
      std::vector<std::string> leftover;
   };

#endif
