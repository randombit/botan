/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/botan.h>
using namespace Botan;

#include "python_botan.h"

class Py_HashFunction : public HashFunction
   {
   public:
      virtual void hash_str(const std::string&) = 0;
      virtual std::string final_str() = 0;

      void clear() throw() {}

      void add_data(const byte input[], u32bit length)
         {
         hash_str(make_string(input, length));
         }

      void final_result(byte output[])
         {
         string2binary(final_str(), output, OUTPUT_LENGTH);
         }

      Py_HashFunction(u32bit digest_size, u32bit block_size) :
         HashFunction(digest_size, block_size) {}
   };

class Wrapped_HashFunction : public HashFunction
   {
   public:
      void add_data(const byte in[], u32bit len) { hash->update(in, len); }
      void final_result(byte out[]) { hash->final(out); }

      void clear() throw() {}

      std::string name() const { return hash->name(); }
      HashFunction* clone() const { return hash->clone(); }

      Wrapped_HashFunction(python::object py_obj, HashFunction* h) :
         HashFunction(h->OUTPUT_LENGTH, h->HASH_BLOCK_SIZE),
         obj(py_obj), hash(h) {}
   private:
      python::object obj;
      HashFunction* hash;
   };

class Py_HashFunction_Wrapper : public Py_HashFunction,
                                public python::wrapper<Py_HashFunction>
   {
   public:
      HashFunction* clone() const
         {
         python::object self = get_owner(this);
         python::object py_clone = self.attr("__class__")();
         HashFunction* hf = python::extract<HashFunction*>(py_clone);
         return new Wrapped_HashFunction(py_clone, hf);
         }

      std::string name() const
         {
         return this->get_override("name")();
         }

      void hash_str(const std::string& in)
         {
         this->get_override("update")(in);
         }

      std::string final_str()
         {
         return this->get_override("final")();
         }

      Py_HashFunction_Wrapper(u32bit digest_size, u32bit block_size) :
         Py_HashFunction(digest_size, block_size) {}
   };

std::string final_str(HashFunction* hash)
   {
   SecureVector<byte> digest = hash->final();
   return std::string((const char*)digest.begin(), digest.size());
   }

void export_hash_functions()
   {
   void (HashFunction::*update_str)(const std::string&) =
      &HashFunction::update;

   python::class_<HashFunction, boost::noncopyable>
      ("HashFunction", python::no_init)
      .def("__init__", python::make_constructor(get_hash))
      .def_readonly("digest_size", &HashFunction::OUTPUT_LENGTH)
      .def("name", &HashFunction::name)
      .def("update", update_str)
      .def("final", final_str);

   python::class_<Py_HashFunction_Wrapper, python::bases<HashFunction>,
                  boost::noncopyable>
      ("HashFunctionImpl", python::init<u32bit, u32bit>())
      .def("name", python::pure_virtual(&Py_HashFunction::name))
      .def("update", python::pure_virtual(&Py_HashFunction::hash_str))
      .def("final", python::pure_virtual(&Py_HashFunction::final_str));
   }
