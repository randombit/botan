/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/botan.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

class Py_MAC
   {
   public:
      u32bit output_length() const { return mac->OUTPUT_LENGTH; }
      u32bit keylength_min() const { return mac->MINIMUM_KEYLENGTH; }
      u32bit keylength_max() const { return mac->MAXIMUM_KEYLENGTH; }
      u32bit keylength_mod() const { return mac->KEYLENGTH_MULTIPLE; }
      std::string name() const { return mac->name(); }
      void clear() throw() { mac->clear(); }

      void set_key(const OctetString& key) { mac->set_key(key); }

      bool valid_keylength(u32bit kl) const
         {
         return mac->valid_keylength(kl);
         }

      void update(const std::string& in) { mac->update(in); }

      std::string final()
         {
         SecureVector<byte> result = mac->final();
         return std::string((const char*)result.begin(), result.size());
         }

      Py_MAC(const std::string& name)
         {
         mac = get_mac(name);
         }
      ~Py_MAC() { delete mac; }
   private:
      MessageAuthenticationCode* mac;
   };

void export_macs()
   {
   python::class_<Py_MAC>("MAC", python::init<std::string>())
      .add_property("output_length", &Py_MAC::output_length)
      .add_property("keylength_min", &Py_MAC::keylength_min)
      .add_property("keylength_max", &Py_MAC::keylength_max)
      .add_property("keylength_mod", &Py_MAC::keylength_mod)
      .add_property("name", &Py_MAC::name)
      .def("valid_keylength", &Py_MAC::valid_keylength)
      .def("set_key", &Py_MAC::set_key)
      .def("clear", &Py_MAC::clear)
      .def("update", &Py_MAC::update)
      .def("final", &Py_MAC::final);
   }
