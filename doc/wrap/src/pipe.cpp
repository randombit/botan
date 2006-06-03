/*************************************************
* Pipe wrapper using Boost.Python                *
* (C) 2005-2006 Jack Lloyd <lloyd@randombit.net> *
*************************************************/

#include <boost/python.hpp>
using namespace boost::python;

#include <botan/pipe.h>
using namespace Botan;

void export_pipe()
   {
   void (Pipe::*pipe_write1)(const std::string&) = &Pipe::write;
   void (Pipe::*pipe_write2)(const byte[], u32bit) = &Pipe::write;

   class_<Pipe, boost::noncopyable>("Pipe")
      .def(init< Python_Filter*, optional<Python_Filter*> >())
      .def("start_msg", &Pipe::start_msg)
      .def("end_msg", &Pipe::end_msg)
      .def("write", pipe_write1)
      .def("write", pipe_write2)
      .def("read_all", &Pipe::read_all_as_string);
   }
