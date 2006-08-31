/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/botan.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

class Py_HashFunction
   {
   public:
      u32bit output_length() const { return hash->OUTPUT_LENGTH; }
      std::string name() const { return hash->name(); }
      void clear() throw() { hash->clear(); }

      void update(const std::string& in) { hash->update(in); }

      std::string final()
         {
         SecureVector<byte> result = hash->final();
         return std::string((const char*)result.begin(), result.size());
         }

      Py_HashFunction(const std::string& name)
         {
         hash = get_hash(name);
         }
      ~Py_HashFunction() { delete hash; }
   private:
      HashFunction* hash;
   };

void export_hash_functions()
   {
   python::class_<Py_HashFunction>("HashFunction", python::init<std::string>())
      .add_property("output_length", &Py_HashFunction::output_length)
      .add_property("name", &Py_HashFunction::name)
      .def("clear", &Py_HashFunction::clear)
      .def("update", &Py_HashFunction::update)
      .def("final", &Py_HashFunction::final);
   }
