/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/dh.h>
#include <botan/look_pk.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

std::string DER_encode_str(const X509_PublicKey* key)
   {
   Pipe pipe;
   X509::encode(*key, pipe, RAW_BER);
   return pipe.read_all_as_string();
   }

std::string get_oid_str(const X509_PublicKey* key)
   {
   try
      {
      return key->get_oid().as_string();
      }
   catch(Lookup_Error)
      {
      return "";
      }
   }

X509_PublicKey* load_key_str(const std::string& file)
   {
   return X509::load_key(file);
   }

void export_pk()
   {
   python::class_<X509_PublicKey, boost::noncopyable>
      ("X509_PublicKey", python::no_init)
      .def("__init__", python::make_constructor(load_key_str))
      .add_property("algo", &X509_PublicKey::algo_name)
      .add_property("max_input_bits", &X509_PublicKey::max_input_bits)
      .add_property("oid", &get_oid_str)
      .def("__str__", &X509::PEM_encode)
      .def("der_encode", &DER_encode_str);
   }
