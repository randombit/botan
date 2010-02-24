/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BOOST_PYTHON_COMMON_H__
#define BOTAN_BOOST_PYTHON_COMMON_H__

#include <botan/exceptn.h>
#include <botan/parsing.h>
#include <botan/secmem.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

extern void export_filters();
extern void export_rsa();
extern void export_x509();

class Bad_Size : public Exception
   {
   public:
      Bad_Size(u32bit got, u32bit expected) :
         Exception("Bad size detected in Python/C++ conversion layer: got " +
                   to_string(got) + " bytes, expected " + to_string(expected))
         {}
   };

inline std::string make_string(const byte input[], u32bit length)
   {
   return std::string((const char*)input, length);
   }

inline std::string make_string(const MemoryRegion<byte>& in)
   {
   return make_string(in.begin(), in.size());
   }

inline void string2binary(const std::string& from, byte to[], u32bit expected)
   {
   if(from.size() != expected)
      throw Bad_Size(from.size(), expected);
   std::memcpy(to, from.data(), expected);
   }

template<typename T>
inline python::object get_owner(T* me)
   {
   return python::object(
      python::handle<>(
         python::borrowed(python::detail::wrapper_base_::get_owner(*me))));
   }

class Python_RandomNumberGenerator
   {
   public:
      Python_RandomNumberGenerator()
         { rng = RandomNumberGenerator::make_rng(); }
      ~Python_RandomNumberGenerator() { delete rng; }

      std::string name() const { return rng->name(); }

      void reseed() { rng->reseed(192); }

      int gen_random_byte() { return rng->next_byte(); }

      std::string gen_random(int n)
         {
         std::string s(n, 0);
         rng->randomize(reinterpret_cast<byte*>(&s[0]), n);
         return s;
         }

      void add_entropy(const std::string& in)
         { rng->add_entropy(reinterpret_cast<const byte*>(in.c_str()), in.length()); }

      RandomNumberGenerator& get_underlying_rng() { return *rng; }
   private:
      RandomNumberGenerator* rng;
   };

#endif
