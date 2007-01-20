/*************************************************
* Configuration Reader Source File               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/config.h>
#include <botan/charset.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <fstream>
#include <map>

namespace Botan {

namespace {

/*************************************************
* Strip comments and whitespace from line        *
*************************************************/
std::string strip_whitespace(const std::string& line)
   {
   bool is_escaped = false, in_quote = false, in_string = false;
   std::string new_line;

   for(std::string::const_iterator j = line.begin(); j != line.end(); ++j)
      {
      const char c = *j;

      if(c == '"' && !is_escaped && !in_string)
         { in_quote = !in_quote; continue; }
      if(c == '\'' && !is_escaped && !in_quote)
         { in_string = !in_string; continue; }
      if(c == '#' && !is_escaped && !in_quote && !in_string)
         return new_line;
      if(c == '\\' && !is_escaped) { is_escaped = true; continue; }

      if(Charset::is_space(c) && !in_quote && !in_string && !is_escaped)
         continue;

      new_line += c;
      is_escaped = false;
      }

   return new_line;
   }

/*************************************************
* Do variable interpolation                      *
*************************************************/
std::string interpolate(const std::string& value,
                        const std::map<std::string, std::string>& variables)
   {
   std::string variable, suffix;

   if(value.find('.') == std::string::npos)
      variable = value;
   else
      {
      variable = value.substr(0, value.find('.'));
      suffix = value.substr(value.find('.'), std::string::npos);
      }

   if(variables.find(variable) != variables.end())
      {
      const std::string result = variables.find(variable)->second;
      if(variable == result)
         return value;
      return interpolate(result, variables) + suffix;
      }
   return value;
   }

}

/*************************************************
* Load a configuration file                      *
*************************************************/
void Config::load_inifile(const std::string& fsname)
   {
   std::ifstream config(fsname.c_str());

   if(!config)
      throw Config_Error("Could not open config file " + fsname);

   u32bit line_no = 0;
   std::string line, section;
   std::map<std::string, std::string> variables;

   while(std::getline(config, line))
      {
      ++line_no;

      line = strip_whitespace(line);

      if(line == "")
         continue;

      if(line[0] == '[' && line[line.size()-1] == ']')
         {
         section = line.substr(1, line.size() - 2);
         if(section == "")
            throw Config_Error("Empty section name", line_no);
         continue;
         }

      if(section == "")
         throw Config_Error("Section must be set before assignment", line_no);

      std::vector<std::string> name_and_value;
      try {
         name_and_value = split_on(line, '=');
         }
      catch(Format_Error)
         {
         throw Config_Error("Bad assignment: " + line, line_no);
         }

      if(name_and_value.size() != 2)
         throw Config_Error("Bad line: " + line, line_no);
      const std::string name = name_and_value[0];
      const std::string value = interpolate(name_and_value[1], variables);

      if(variables.find(name) == variables.end())
         variables[name] = value;

      if(section == "oids")
         {
         set("oid2str", name, value, false);
         set("str2oid", value, name, false);
         }
      else if(section == "aliases")
         set("alias", name, value);
      else
         set("conf", section + '/' + name, value);
      }
   }

}
