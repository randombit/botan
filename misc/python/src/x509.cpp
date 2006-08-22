/*************************************************
* Wrappers for X.509 types                       *
* (C) 2005-2006 Jack Lloyd <lloyd@randombit.net> *
*************************************************/

#include <boost/python.hpp>
using namespace boost::python;

#include <botan/oids.h>
#include <botan/x509_key.h>
#include <botan/x509cert.h>
using namespace Botan;

template<typename C>
list vector_to_list(const C& in)
   {
   list out;
   typename C::const_iterator i = in.begin();
   while(i != in.end()) { out.append(*i); ++i; }
   return out;
   }

template<typename C>
std::vector<std::string> oid_lookup(const C& in)
   {
   std::vector<std::string> out;
   typename C::const_iterator i = in.begin();
   while(i != in.end())
      {
      OID oid(*i);
      std::string string_rep = OIDS::lookup(oid);

      out.push_back(OIDS::lookup(oid));
      ++i;
      }
   return out;
   }

list get_subject_info(const X509_Certificate* cert,
                      const std::string& type)
   {
   return vector_to_list(cert->subject_info(type));
   }

list get_issuer_info(const X509_Certificate* cert,
                     const std::string& type)
   {
   return vector_to_list(cert->issuer_info(type));
   }

list get_policies(const X509_Certificate* cert)
   {
   return vector_to_list(cert->policies());
   }

list get_ex_constraints(const X509_Certificate* cert)
   {
   return vector_to_list(oid_lookup(cert->ex_constraints()));
   }

void export_x509()
   {
   class_<X509_Certificate>("X509_Certificate", init<std::string>())
      .add_property("version", &X509_Certificate::x509_version)
      .add_property("is_CA", &X509_Certificate::is_CA_cert)
      .add_property("self_signed", &X509_Certificate::is_self_signed)
      .add_property("pathlimit", &X509_Certificate::path_limit)
      .def("start_time", &X509_Certificate::start_time)
      .def("end_time", &X509_Certificate::end_time)
      .def("subject_info", get_subject_info)
      .def("issuer_info", get_issuer_info)
      .def("ex_constraints", get_ex_constraints)
      .def("policies", get_policies);
   }
