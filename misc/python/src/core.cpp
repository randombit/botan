/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/botan.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

extern void export_block_ciphers();
extern void export_filters();
extern void export_pk();
extern void export_x509();

BOOST_PYTHON_MODULE(_botan)
   {
   python::class_<LibraryInitializer>("LibraryInitializer")
      .def(python::init< python::optional<std::string> >());

   python::class_<OctetString>("OctetString")
      .def(python::init< python::optional<std::string> >())
      .def(python::init< u32bit >())
      .def("__str__", &OctetString::as_string)
      .def("__len__", &OctetString::length);

   python::enum_<Cipher_Dir>("cipher_dir")
      .value("encryption", ENCRYPTION)
      .value("decryption", DECRYPTION);

   export_block_ciphers();
   export_filters();
   export_pk();
   export_x509();
   }
