/*************************************************
* Wrappers for Botan Filters                     *
* (C) 2005-2006 Jack Lloyd <lloyd@randombit.net> *
*************************************************/

#include <boost/python.hpp>
using namespace boost::python;

#include <botan/pipe.h>
#include <botan/lookup.h>
using namespace Botan;

class Python_Filter : public Fanout_Filter, public wrapper<Fanout_Filter>
   {
   public:
      virtual void write(const byte in[], u32bit len)
         {
         this->get_override("write")(in, len);
         }
      virtual void start_msg()
         {
         if(override start_msg = this->get_override("start_msg"))
            start_msg();
         Filter::start_msg();
         }
      virtual void end_msg()
         {
         if(override end_msg = this->get_override("end_msg"))
            end_msg();
         Filter::end_msg();
         }

      Python_Filter(Filter* f)
         {
         if(f) { attach(f); incr_owns(); }
         }
   };

Python_Filter* make_filter1(const std::string& name)
   {
   printf("Trying to make filter of type %s\n", name.c_str());

   if(have_hash(name))
      return new Python_Filter(new Hash_Filter(name));
   if(name == "Hex_Encoder")
      return new Python_Filter(new Hex_Encoder);

   return 0;
   }

// FIXME: add new wrapper for Keyed_Filter here
Python_Filter* make_filter2(const std::string& name,
                            const SymmetricKey& key)
   {
   printf("Trying to make a filter of type %s (key %s)\n", name.c_str(),
          key.as_string().c_str());
   return 0;
   }

void export_filters()
   {
   class_<Python_Filter, boost::noncopyable>("Filter", no_init)
      .def("write", &Filter::write)
      .def("start_msg", &Filter::start_msg)
      .def("end_msg", &Filter::end_msg);

   def("make_filter", make_filter1,
       return_value_policy<manage_new_object>());
   def("make_filter", make_filter2,
       return_value_policy<manage_new_object>());
   }
