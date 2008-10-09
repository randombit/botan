/*************************************************
* SWIG Interface for basic Botan interface       *
* (C) 1999-2003 Jack Lloyd                       *
*************************************************/

#include "base.h"
#include <botan/init.h>

#include <stdio.h>

/*************************************************
* Initialize the library                         *
*************************************************/
LibraryInitializer::LibraryInitializer(const char* args)
   {
   Botan::Init::initialize(args);
   }

/*************************************************
* Shut down the library                          *
*************************************************/
LibraryInitializer::~LibraryInitializer()
   {
   Botan::Init::deinitialize();
   }

/*************************************************
* Create a SymmetricKey                          *
*************************************************/
SymmetricKey::SymmetricKey(const std::string& str)
   {
   key = new Botan::SymmetricKey(str);
   printf("STR CON: %p %p\n", this, key);
   }

/*************************************************
* Create a SymmetricKey                          *
*************************************************/
SymmetricKey::SymmetricKey(u32bit n)
   {
   key = new Botan::SymmetricKey(n);
   printf("N CON: %p %p\n", this, key);
   }

/*************************************************
* Destroy a SymmetricKey                         *
*************************************************/
SymmetricKey::~SymmetricKey()
   {
   printf("DESTR: %p %p\n", this, key);
   delete key;
   key = 0;
   //printf("deleted\n");
   }

/*************************************************
* Create an InitializationVector                 *
*************************************************/
InitializationVector::InitializationVector(const std::string& str) : iv(str)
   {
   }
