/*************************************************
* SWIG Interface for Botan                       *
*************************************************/
%module botan

%include "typemaps.i"
%include "std_string.i"
%include "exception.i"
%include "constraints.i"
%include "carrays.i"

%{
#include "base.h"
%}

%exception {
   try {
      $action
   }
   catch(std::exception& e)
   {
      SWIG_exception(SWIG_RuntimeError, e.what());
   }
}

%include "base.h"
