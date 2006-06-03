/*************************************************
* Boost.Python module definition                 *
* (C) 2005-2006 Jack Lloyd <lloyd@randombit.net> *
*************************************************/

#include <boost/python.hpp>
using namespace boost::python;

extern void export_basic_types();
extern void export_filters();
extern void export_pipe();
extern void export_x509();

BOOST_PYTHON_MODULE(_botan)
   {
   export_basic_types();
   export_filters();
   export_pipe();
   export_x509();
   }
