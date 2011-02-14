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
#include <botan/x509stor.h>
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
   memvec_to_hexstr<MemoryVector<byte> >();

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

   python::enum_<X509_Code>("verify_result")
      .value("verified", VERIFIED)
      .value("unknown_x509_error", UNKNOWN_X509_ERROR)
      .value("cannot_establish_trust", CANNOT_ESTABLISH_TRUST)
      .value("cert_chain_too_long", CERT_CHAIN_TOO_LONG)
      .value("signature_error", SIGNATURE_ERROR)
      .value("policy_error", POLICY_ERROR)
      .value("invalid_usage", INVALID_USAGE)
      .value("cert_format_error", CERT_FORMAT_ERROR)
      .value("cert_issuer_not_found", CERT_ISSUER_NOT_FOUND)
      .value("cert_not_yet_valid", CERT_NOT_YET_VALID)
      .value("cert_has_expired", CERT_HAS_EXPIRED)
      .value("cert_is_revoked", CERT_IS_REVOKED)
      .value("crl_format_error", CRL_FORMAT_ERROR)
      .value("crl_issuer_not_found", CRL_ISSUER_NOT_FOUND)
      .value("crl_not_yet_valid", CRL_NOT_YET_VALID)
      .value("crl_has_expired", CRL_HAS_EXPIRED)
      .value("ca_cert_cannot_sign", CA_CERT_CANNOT_SIGN)
      .value("ca_cert_not_for_cert_issuer", CA_CERT_NOT_FOR_CERT_ISSUER)
      .value("ca_cert_not_for_crl_issuer", CA_CERT_NOT_FOR_CRL_ISSUER);

   python::enum_<X509_Store::Cert_Usage>("cert_usage")
      .value("any", X509_Store::ANY)
      .value("tls_server", X509_Store::TLS_SERVER)
      .value("tls_client", X509_Store::TLS_CLIENT)
      .value("code_signing", X509_Store::CODE_SIGNING)
      .value("email_protection", X509_Store::EMAIL_PROTECTION)
      .value("time_stamping", X509_Store::TIME_STAMPING)
      .value("crl_signing", X509_Store::CRL_SIGNING);

      {
      python::scope in_class = 
         python::class_<X509_Store>("X509_Store")
         .def("add_cert", &X509_Store::add_cert, add_cert_ols())
         .def("validate", &X509_Store::validate_cert, validate_cert_ols())
         .def("add_crl", &X509_Store::add_crl);
      }
   }
