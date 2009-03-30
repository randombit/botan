/*
* User Interface
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ui.h>

namespace Botan {

/*
* Get a passphrase from the user
*/
std::string User_Interface::get_passphrase(const std::string&,
                                           const std::string&,
                                           UI_Result& action) const
   {
   action = OK;

   if(!first_try)
      action = CANCEL_ACTION;

   return preset_passphrase;
   }

/*
* User_Interface Constructor
*/
User_Interface::User_Interface(const std::string& preset) :
   preset_passphrase(preset)
   {
   first_try = true;
   }

}
