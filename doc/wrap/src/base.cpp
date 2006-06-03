/*************************************************
* Wrappers for basic Botan types                 *
* (C) 2005-2006 Jack Lloyd <lloyd@randombit.net> *
*************************************************/

#include <boost/python.hpp>
using namespace boost::python;

#include <botan/init.h>
#include <botan/symkey.h>
using namespace Botan;

void export_basic_types()
   {
   class_<LibraryInitializer>("LibraryInitializer")
      .def(init< optional<std::string> >());

   class_<OctetString>("OctetString")
      .def(init< optional<std::string> >())
      .def("as_string", &OctetString::as_string)
      .def("length", &OctetString::length)
      .def(self ^= self);

   class_<SymmetricKey, bases<OctetString> >("SymmetricKey")
      .def(init< optional<std::string> >())
      .def(init< u32bit >());

   class_<InitializationVector, bases<OctetString> >("InitializationVector")
      .def(init< optional<std::string> >())
      .def(init< u32bit >());
   }
