/*************************************************
* Wrappers for X.509 types                       *
* (C) 2005-2006 Jack Lloyd <lloyd@randombit.net> *
*************************************************/

#include <boost/python.hpp>
using namespace boost::python;

#include <botan/x509_key.h>

void export_x509()
   {
   class_<X509_PublicKey>("x509_key", no_init)
      .def(
   }
