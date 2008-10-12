
#ifndef BOTAN_BOOST_PYTHON_COMMON_H__
#define BOTAN_BOOST_PYTHON_COMMON_H__

#include <botan/base.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;


extern void export_block_ciphers();
extern void export_stream_ciphers();
extern void export_hash_functions();
extern void export_macs();
extern void export_filters();
extern void export_pk();
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

#endif
