/*
* STL Utility Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_STL_UTIL_H__
#define BOTAN_STL_UTIL_H__

#include <map>

namespace Botan {

/**
* Copy-on-Predicate Algorithm
* @param current the first iterator value
* @param end the final iterator value
* @param dest an output iterator
* @param copy_p the predicate
*/
template<typename InputIterator, typename OutputIterator, typename Predicate>
OutputIterator copy_if(InputIterator current, InputIterator end,
                       OutputIterator dest, Predicate copy_p)
   {
   while(current != end)
      {
      if(copy_p(*current))
         *dest++ = *current;
      ++current;
      }
   return dest;
   }

/**
* Searching through a std::map
* @param mapping the map to search
* @param key is what to look for
* @param null_result is the value to return if key is not in mapping
* @return mapping[key] or null_result
*/
template<typename K, typename V>
inline V search_map(const std::map<K, V>& mapping,
                    const K& key,
                    const V& null_result = V())
   {
   typename std::map<K, V>::const_iterator i = mapping.find(key);
   if(i == mapping.end())
      return null_result;
   return i->second;
   }

/**
* Function adaptor for delete operation
*/
template<class T>
class del_fun : public std::unary_function<T, void>
   {
   public:
      void operator()(T* ptr) { delete ptr; }
   };

/**
* Delete the second half of a pair of objects
*/
template<typename Pair>
void delete2nd(Pair& pair)
   {
   delete pair.second;
   }

/**
* Insert a key/value pair into a multimap
*/
template<typename K, typename V>
void multimap_insert(std::multimap<K, V>& multimap,
                     const K& key, const V& value)
   {
#if defined(BOTAN_BUILD_COMPILER_IS_SUN_STUDIO)
   // Work around a strange bug in Sun Studio
   multimap.insert(std::make_pair<const K, V>(key, value));
#else
   multimap.insert(std::make_pair(key, value));
#endif
   }

}

#endif
