/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/init.h>
#include <botan/symkey.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

extern void export_filters();
extern void export_pipe();
extern void export_x509();

BOOST_PYTHON_MODULE(_botan)
   {
   python::class_<LibraryInitializer>("LibraryInitializer")
      .def(python::init< python::optional<std::string> >());

   python::class_<OctetString>("OctetString")
      .def(python::init< python::optional<std::string> >())
      .def("as_string", &OctetString::as_string)
      .def("length", &OctetString::length)
      .def(python::self ^= python::self);

   python::class_<SymmetricKey, python::bases<OctetString> >("SymmetricKey")
      .def(python::init< python::optional<std::string> >())
      .def(python::init< u32bit >());

   python::class_<InitializationVector, python::bases<OctetString> >
      ("InitializationVector")
      .def(python::init< python::optional<std::string> >())
      .def(python::init< u32bit >());

   python::enum_<Cipher_Dir>("cipher_dir")
      .value("encryption", ENCRYPTION)
      .value("decryption", DECRYPTION);

   export_filters();
   export_pipe();
   export_x509();
   }
