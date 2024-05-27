/**
 * Any Map
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */
#ifndef BOTAN_ANY_MAP_H_
#define BOTAN_ANY_MAP_H_

#include <botan/exceptn.h>

#include <any>
#include <map>
#include <string>

class Any_Map : public std::map<std::string, std::any> {
   public:
      template <typename... Ts>
      Any_Map(std::pair<std::string, Ts>... key_value_pair) {
         (this->insert(key_value_pair), ...);
      }

      template <typename T>
      T get(const std::string& key) const {
         auto i = this->find(key);
         if(i == this->end()) {
            throw Botan::Invalid_Argument("Key not found");
         }
         return std::any_cast<T>(i->second);
      }

      template <typename T>
      T get_or(const std::string& key, T default_value) const {
         auto i = this->find(key);
         if(i == this->end()) {
            return default_value;
         }
         return std::any_cast<T>(i->second);
      }

      template <typename T>
      void set(const std::string& key, const T& val) {
         this->operator[](key) = val;
      }

      template <typename T>
      bool has(const std::string& key) const {
         return (this->find(key) != this->end());
      }
};

#endif  // BOTAN_ANY_MAP_H_
