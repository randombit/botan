/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/botan.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

#include "python_botan.h"

class Python_RandomNumberGenerator
   {
   public:
      Python_RandomNumberGenerator()
         { rng = RandomNumberGenerator::make_rng(); }
      ~Python_RandomNumberGenerator() { delete rng; }

      std::string name() const { return rng->name(); }

      void reseed() { rng->reseed(); }

      int gen_random_byte() { return rng->next_byte(); }

      std::string gen_random(int n)
         {
         std::string s(n, 0);
         rng->randomize(reinterpret_cast<byte*>(&s[0]), n);
         return s;
         }

      void add_entropy(const std::string& in)
         { rng->add_entropy(reinterpret_cast<const byte*>(in.c_str()), in.length()); }

   private:
      RandomNumberGenerator* rng;
   };

BOOST_PYTHON_MODULE(_botan)
   {
   python::class_<LibraryInitializer>("LibraryInitializer")
      .def(python::init< python::optional<std::string> >());

   python::class_<Python_RandomNumberGenerator>("RandomNumberGenerator")
      .def(python::init<>())
      .def("__str__", &Python_RandomNumberGenerator::name)
      .def("name", &Python_RandomNumberGenerator::name)
      .def("reseed", &Python_RandomNumberGenerator::reseed)
      .def("add_entropy", &Python_RandomNumberGenerator::add_entropy)
      .def("gen_random_byte", &Python_RandomNumberGenerator::gen_random_byte)
      .def("gen_random", &Python_RandomNumberGenerator::gen_random);

   python::class_<OctetString>("OctetString")
      .def(python::init< python::optional<std::string> >())
      //.def(python::init< u32bit >())
      .def("__str__", &OctetString::as_string)
      .def("__len__", &OctetString::length);

   python::enum_<Cipher_Dir>("cipher_dir")
      .value("encryption", ENCRYPTION)
      .value("decryption", DECRYPTION);

   export_block_ciphers();
   export_stream_ciphers();
   export_hash_functions();
   export_macs();

   export_filters();
   export_pk();
   export_x509();
   }
