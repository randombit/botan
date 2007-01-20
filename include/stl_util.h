/*************************************************
* STL Utility Functions Header File              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_STL_UTIL_H__
#define BOTAN_STL_UTIL_H__

#include <map>

namespace Botan {

/*************************************************
* Copy-on-Predicate Algorithm                    *
*************************************************/
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

/*************************************************
* Searching through a std::map                   *
*************************************************/
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

template<typename K, typename V, typename R>
inline R search_map(const std::map<K, V>& mapping, const K& key,
                    const R& null_result, const R& found_result)
   {
   typename std::map<K, V>::const_iterator i = mapping.find(key);
   if(i == mapping.end())
      return null_result;
   return found_result;
   }

/*************************************************
* Function adaptor for delete operation          *
*************************************************/
template<class T>
class del_fun : public std::unary_function<T, void>
   {
   public:
      void operator()(T* ptr) { delete ptr; }
   };

/*************************************************
* Delete the second half of a pair of objects    *
*************************************************/
template<typename Pair>
void delete2nd(Pair& pair)
   {
   delete pair.second;
   }

/*************************************************
* Insert a key/value pair into a multimap        *
*************************************************/
template<typename K, typename V>
void multimap_insert(std::multimap<K, V>& multimap,
                     const K& key, const V& value)
   {
   multimap.insert(std::make_pair(key, value));
   }

}

#endif
