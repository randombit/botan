/*
* Boost.Python module definition
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/oids.h>
#include <botan/pipe.h>
#include <botan/filters.h>
#include <botan/x509cert.h>
#include <botan/x509_crl.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

template<typename T>
class vector_to_list
   {
   public:
      static PyObject* convert(const std::vector<T>& in)
         {
         python::list out;
         typename std::vector<T>::const_iterator i = in.begin();
         while(i != in.end())
            {
            out.append(*i);
            ++i;
            }
         return python::incref(out.ptr());
         }

      vector_to_list()
         {
         python::to_python_converter<std::vector<T>, vector_to_list<T> >();
         }
   };

template<typename T>
class memvec_to_hexstr
   {
   public:
      static PyObject* convert(const T& in)
         {
         Pipe pipe(new Hex_Encoder);
         pipe.process_msg(in);
         std::string result = pipe.read_all_as_string();
         return python::incref(python::str(result).ptr());
         }

      memvec_to_hexstr()
         {
         python::to_python_converter<T, memvec_to_hexstr<T> >();
         }
   };

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(add_cert_ols, add_cert, 1, 2)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(validate_cert_ols, validate_cert, 1, 2)

void export_x509()
   {
   vector_to_list<std::string>();
   vector_to_list<X509_Certificate>();
   memvec_to_hexstr<std::vector<byte> >();

   python::class_<X509_Certificate>
      ("X509_Certificate", python::init<std::string>())
      .def(python::self == python::self)
      .def(python::self != python::self)
      .add_property("version", &X509_Certificate::x509_version)
      .add_property("is_CA", &X509_Certificate::is_CA_cert)
      .add_property("self_signed", &X509_Certificate::is_self_signed)
      .add_property("pathlimit", &X509_Certificate::path_limit)
      .add_property("as_pem", &X509_Object::PEM_encode)
      .def("start_time", &X509_Certificate::start_time)
      .def("end_time", &X509_Certificate::end_time)
      .def("subject_info", &X509_Certificate::subject_info)
      .def("issuer_info", &X509_Certificate::issuer_info)
      .def("ex_constraints", &X509_Certificate::ex_constraints)
      .def("policies", &X509_Certificate::policies)
      .def("subject_key_id", &X509_Certificate::subject_key_id)
      .def("authority_key_id", &X509_Certificate::authority_key_id);

   python::class_<X509_CRL>
      ("X509_CRL", python::init<std::string>())
      .add_property("as_pem", &X509_Object::PEM_encode);
   }
