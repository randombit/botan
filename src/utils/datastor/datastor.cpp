/*
* Data Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/datastor.h>
#include <botan/exceptn.h>
#include <botan/parsing.h>
#include <botan/stl_util.h>
#include <botan/filters.h>

namespace Botan {

/*
* Data_Store Equality Comparison
*/
bool Data_Store::operator==(const Data_Store& other) const
   {
   return (contents == other.contents);
   }

/*
* Check if this key has at least one value
*/
bool Data_Store::has_value(const std::string& key) const
   {
   return (contents.lower_bound(key) != contents.end());
   }

/*
* Search based on an arbitrary predicate
*/
std::multimap<std::string, std::string> Data_Store::search_for(
   std::function<bool (std::string, std::string)> predicate) const
   {
   std::multimap<std::string, std::string> out;

   for(auto i = contents.begin(); i != contents.end(); ++i)
      if(predicate(i->first, i->second))
         out.insert(std::make_pair(i->first, i->second));

   return out;
   }

/*
* Search based on key equality
*/
std::vector<std::string> Data_Store::get(const std::string& looking_for) const
   {
   std::vector<std::string> out;
   auto range = contents.equal_range(looking_for);
   for(auto i = range.first; i != range.second; ++i)
      out.push_back(i->second);
   return out;
   }

/*
* Get a single atom
*/
std::string Data_Store::get1(const std::string& key) const
   {
   std::vector<std::string> vals = get(key);

   if(vals.empty())
      throw Invalid_State("Data_Store::get1: Not values for " + key);
   if(vals.size() > 1)
      throw Invalid_State("Data_Store::get1: More than one value for " + key);

   return vals[0];
   }

/*
* Get a single MemoryVector atom
*/
MemoryVector<byte>
Data_Store::get1_memvec(const std::string& key) const
   {
   std::vector<std::string> vals = get(key);

   if(vals.size() > 1)
      throw Invalid_State("Data_Store::get1_memvec: Multiple values for " +
                          key);

   if(vals.empty())
      return MemoryVector<byte>();

   Pipe pipe(new Hex_Decoder(FULL_CHECK));
   pipe.start_msg();
   if(vals.size())
      pipe.write(vals[0]);
   pipe.end_msg();
   return pipe.read_all();
   }

/*
* Get a single u32bit atom
*/
u32bit Data_Store::get1_u32bit(const std::string& key,
                               u32bit default_val) const
   {
   std::vector<std::string> vals = get(key);

   if(vals.empty())
      return default_val;
   else if(vals.size() > 1)
      throw Invalid_State("Data_Store::get1_u32bit: Multiple values for " +
                          key);

   return to_u32bit(vals[0]);
   }

/*
* Insert a single key and value
*/
void Data_Store::add(const std::string& key, const std::string& val)
   {
   multimap_insert(contents, key, val);
   }

/*
* Insert a single key and value
*/
void Data_Store::add(const std::string& key, u32bit val)
   {
   add(key, std::to_string(val));
   }

/*
* Insert a single key and value
*/
void Data_Store::add(const std::string& key, const MemoryRegion<byte>& val)
   {
   Pipe pipe(new Hex_Encoder);
   pipe.process_msg(val);
   add(key, pipe.read_all_as_string());
   }

/*
* Insert a mapping of key/value pairs
*/
void Data_Store::add(const std::multimap<std::string, std::string>& in)
   {
   std::multimap<std::string, std::string>::const_iterator i = in.begin();
   while(i != in.end())
      {
      contents.insert(*i);
      ++i;
      }
   }

}
