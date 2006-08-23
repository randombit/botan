/*************************************************
* Wrappers for Botan Filters                     *
* (C) 2005-2006 Jack Lloyd <lloyd@randombit.net> *
*************************************************/

#include <boost/python.hpp>
using namespace boost::python;

#include <botan/pipe.h>
#include <botan/lookup.h>
using namespace Botan;

Filter* return_or_raise(Filter* f, const std::string& name)
   {
   if(f)
      return f;
   throw Invalid_Argument("Filter " + name + " not found");
   }

Filter* make_filter1(const std::string& name)
   {
   if(have_hash(name))
      return new Hash_Filter(name);
   else if(name == "Hex_Encoder")
      return new Hex_Encoder;
   else if(name == "Hex_Decoder")
      return new Hex_Decoder;

   throw Invalid_Argument("Filter " + name + " not found");
   }

Filter* make_filter2(const std::string& name,
                     const SymmetricKey& key)
   {
   if(have_mac(name))
      return new MAC_Filter(name, key);
   else if(have_stream_cipher(name))
      return new StreamCipher_Filter(name, key);

   throw Invalid_Argument("Filter " + name + " not found");
   }

// FIXME: add new wrapper for Keyed_Filter here
Filter* make_filter3(const std::string& name,
                     const SymmetricKey& key,
                     Cipher_Dir direction)
   {
   return return_or_raise(get_cipher(name, key, direction), name);
   }

Filter* make_filter4(const std::string& name,
                     const SymmetricKey& key,
                     const InitializationVector& iv,
                     Cipher_Dir direction)
   {
   return return_or_raise(get_cipher(name, key, iv, direction), name);
   }

void export_filters()
   {
   class_<Filter, std::auto_ptr<Filter>, boost::noncopyable>
      ("__Internal_FilterObj", no_init);

   def("make_filter", make_filter1,
       return_value_policy<manage_new_object>());
   def("make_filter", make_filter2,
       return_value_policy<manage_new_object>());
   def("make_filter", make_filter3,
       return_value_policy<manage_new_object>());
   def("make_filter", make_filter4,
       return_value_policy<manage_new_object>());
   }

void append_filter(Pipe& pipe, std::auto_ptr<Filter> filter)
   {
   pipe.append(filter.get());
   filter.release();
   }

void prepend_filter(Pipe& pipe, std::auto_ptr<Filter> filter)
   {
   pipe.prepend(filter.get());
   filter.release();
   }

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(rallas_ovls, read_all_as_string, 0, 1)

void export_pipe()
   {
   void (Pipe::*pipe_write_str)(const std::string&) = &Pipe::write;
   void (Pipe::*pipe_process_str)(const std::string&) = &Pipe::process_msg;

   class_<Pipe, boost::noncopyable>("PipeObj")
      .def(init<>())
      .def_readonly("LAST_MESSAGE", &Pipe::LAST_MESSAGE)
      .def_readonly("DEFAULT_MESSAGE", &Pipe::DEFAULT_MESSAGE)
      .add_property("default_msg", &Pipe::default_msg, &Pipe::set_default_msg)
      .add_property("msg_count", &Pipe::message_count)
      .def("append", append_filter)
      .def("prepend", prepend_filter)
      .def("reset", &Pipe::reset)
      .def("pop", &Pipe::pop)
      .def("end_of_data", &Pipe::end_of_data)
      .def("start_msg", &Pipe::start_msg)
      .def("end_msg", &Pipe::end_msg)
      .def("write", pipe_write_str)
      .def("process_msg", pipe_process_str)
      .def("read_all", &Pipe::read_all_as_string, rallas_ovls());
   }
