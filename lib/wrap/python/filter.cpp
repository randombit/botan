/*
* Boost.Python module definition
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <boost/python.hpp>
using namespace boost::python;

#include <botan/pipe.h>
#include <botan/lookup.h>
using namespace Botan;

class Py_Filter : public Filter
   {
   public:
      virtual void write_str(const std::string&) = 0;

      std::string name() const { return "Py_Filter_FIXME"; }

      void write(const byte data[], size_t length)
         {
         write_str(std::string((const char*)data, length));
         }

      void send_str(const std::string& str)
         {
         send((const byte*)str.data(), str.length());
         }
   };

class FilterWrapper : public Py_Filter, public wrapper<Py_Filter>
   {
   public:
      void start_msg()
         {
         if(override start_msg = this->get_override("start_msg"))
            start_msg();
         }

      void end_msg()
         {
         if(override end_msg = this->get_override("end_msg"))
            end_msg();
         }

      void default_start_msg() {}
      void default_end_msg() {}

      virtual void write_str(const std::string& str)
         {
         this->get_override("write")(str);
         }
   };

Filter* return_or_raise(Filter* filter, const std::string& name)
   {
   if(filter)
      return filter;
   throw Invalid_Argument("Filter " + name + " could not be found");
   }

Filter* make_filter1(const std::string& name)
   {
   Filter* filter = 0;

   if(have_hash(name))               filter = new Hash_Filter(name);
   else if(name == "Hex_Encoder")    filter = new Hex_Encoder;
   else if(name == "Hex_Decoder")    filter = new Hex_Decoder;
   else if(name == "Base64_Encoder") filter = new Base64_Encoder;
   else if(name == "Base64_Decoder") filter = new Base64_Decoder;

   return return_or_raise(filter, name);
   }

Filter* make_filter2(const std::string& name,
                     const SymmetricKey& key)
   {
   Filter* filter = 0;

   if(have_mac(name))
      filter = new MAC_Filter(name, key);
   else if(have_stream_cipher(name))
      filter = new StreamCipher_Filter(name, key);

   return return_or_raise(filter, name);
   }

// FIXME: add new wrapper for Keyed_Filter here
Filter* make_filter3(const std::string& name,
                     const SymmetricKey& key,
                     Cipher_Dir direction)
   {
   return return_or_raise(
      get_cipher(name, key, direction),
      name);
   }

Filter* make_filter4(const std::string& name,
                     const SymmetricKey& key,
                     const InitializationVector& iv,
                     Cipher_Dir direction)
   {
   return return_or_raise(
      get_cipher(name, key, iv, direction),
      name);
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

void do_send(std::auto_ptr<FilterWrapper> filter, const std::string& data)
   {
   filter->send_str(data);
   }

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(rallas_ovls, read_all_as_string, 0, 1)

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

   // This might not work - Pipe will delete the filter, but Python
   // might have allocated the space with malloc() or who-knows-what -> bad
   class_<FilterWrapper, std::auto_ptr<FilterWrapper>,
          bases<Filter>, boost::noncopyable>
      ("FilterObj")
      .def("write", pure_virtual(&Py_Filter::write_str))
      .def("send", &do_send)
      .def("start_msg", &Filter::start_msg, &FilterWrapper::default_start_msg)
      .def("end_msg", &Filter::end_msg, &FilterWrapper::default_end_msg);

   implicitly_convertible<std::auto_ptr<FilterWrapper>,
                          std::auto_ptr<Filter> >();

   void (Pipe::*pipe_write_str)(const std::string&) = &Pipe::write;
   void (Pipe::*pipe_process_str)(const std::string&) = &Pipe::process_msg;

   class_<Pipe, boost::noncopyable>("PipeObj")
      .def(init<>())
      /*
      .def_readonly("LAST_MESSAGE", &Pipe::LAST_MESSAGE)
      .def_readonly("DEFAULT_MESSAGE", &Pipe::DEFAULT_MESSAGE)
      */
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
