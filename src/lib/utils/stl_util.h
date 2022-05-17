/*
* STL Utility Functions
* (C) 1999-2007 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_STL_UTIL_H_
#define BOTAN_STL_UTIL_H_

#include <vector>
#include <variant>
#include <string>
#include <map>
#include <set>
#include <tuple>

#include <botan/secmem.h>

namespace Botan {

inline std::vector<uint8_t> to_byte_vector(const std::string& s)
   {
   return std::vector<uint8_t>(s.cbegin(), s.cend());
   }

inline std::string to_string(const secure_vector<uint8_t> &bytes)
   {
   return std::string(bytes.cbegin(), bytes.cend());
   }

/**
* Return the keys of a map as a std::set
*/
template<typename K, typename V>
std::set<K> map_keys_as_set(const std::map<K, V>& kv)
   {
   std::set<K> s;
   for(auto&& i : kv)
      {
      s.insert(i.first);
      }
   return s;
   }

/*
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
   auto i = mapping.find(key);
   if(i == mapping.end())
      return null_result;
   return i->second;
   }

template<typename K, typename V, typename R>
inline R search_map(const std::map<K, V>& mapping, const K& key,
                    const R& null_result, const R& found_result)
   {
   auto i = mapping.find(key);
   if(i == mapping.end())
      return null_result;
   return found_result;
   }

/*
* Insert a key/value pair into a multimap
*/
template<typename K, typename V>
void multimap_insert(std::multimap<K, V>& multimap,
                     const K& key, const V& value)
   {
   multimap.insert(std::make_pair(key, value));
   }

/**
* Existence check for values
*/
template<typename T>
bool value_exists(const std::vector<T>& vec,
                  const T& val)
   {
   for(size_t i = 0; i != vec.size(); ++i)
      if(vec[i] == val)
         return true;
   return false;
   }

template<typename T, typename Pred>
void map_remove_if(Pred pred, T& assoc)
   {
   auto i = assoc.begin();
   while(i != assoc.end())
      {
      if(pred(i->first))
         assoc.erase(i++);
      else
         i++;
      }
   }

/**
 * Concatenate an arbitrary number of buffers.
 * @return the concatenation of \p buffers as the container type of the first buffer
 */
template <typename... Ts>
decltype(auto) concat(Ts&& ...buffers)
   {
   static_assert(sizeof...(buffers) > 0, "concat requires at least one buffer");

   // TODO: C++20: use std::remove_cvref_t
   using result_t = std::remove_cv_t<std::remove_reference_t<std::tuple_element_t<0, std::tuple<Ts...>>>>;
   result_t result;
   result.reserve((buffers.size() + ...));
   (result.insert(result.end(), buffers.begin(), buffers.end()), ...);
   return result;
   }

/**
 * Concatenate an arbitrary number of buffers and define the output buffer
 * type as a mandatory template parameter.
 * @return the concatenation of \p buffers as the user-defined container type
 */
template <typename ResultT, typename... Ts>
ResultT concat_as(Ts&& ...buffers)
   {
   return concat(ResultT(), std::forward<Ts>(buffers)...);
   }

template<typename... Alts, typename... Ts>
constexpr bool holds_any_of(const std::variant<Ts...>& v) noexcept {
    return (std::holds_alternative<Alts>(v) || ...);
}

// This is a helper utility to emulate pattern matching with std::visit.
// See https://en.cppreference.com/w/cpp/utility/variant/visit for more info.
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
// explicit deduction guide (not needed as of C++20)
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

}

#endif
