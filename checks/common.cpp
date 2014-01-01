/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <iostream>
#include <vector>
#include <string>

#include "common.h"

void strip_comments(std::string& line)
   {
   if(line.find('#') != std::string::npos)
      line = line.erase(line.find('#'), std::string::npos);
   }

void strip_newlines(std::string& line)
   {
   while(line.find('\n') != std::string::npos)
      line = line.erase(line.find('\n'), 1);
   }

/* Strip comments, whitespace, etc */
void strip(std::string& line)
   {
   strip_comments(line);

#if 0
   while(line.find(' ') != std::string::npos)
      line = line.erase(line.find(' '), 1);
#endif

   while(line.find('\t') != std::string::npos)
      line = line.erase(line.find('\t'), 1);
   }

std::vector<std::string> parse(const std::string& line)
   {
   const char DELIMITER = ':';
   std::vector<std::string> substr;
   std::string::size_type start = 0, end = line.find(DELIMITER);
   while(end != std::string::npos)
      {
      substr.push_back(line.substr(start, end-start));
      start = end+1;
      end = line.find(DELIMITER, start);
      }
   if(line.size() > start)
      substr.push_back(line.substr(start));
   while(substr.size() <= 4) // at least 5 substr, some possibly empty
      substr.push_back("");
   return substr;
   }

