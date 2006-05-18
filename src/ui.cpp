/*************************************************
* User Interface Source File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/ui.h>

namespace Botan {

/*************************************************
* Get a passphrase from the user                 *
*************************************************/
std::string User_Interface::get_passphrase(const std::string&,
                                           const std::string&,
                                           UI_Result& action) const
   {
   action = OK;

   if(!first_try)
      action = CANCEL_ACTION;

   return preset_passphrase;
   }

/*************************************************
* User_Interface Constructor                     *
*************************************************/
User_Interface::User_Interface(const std::string& preset) :
   preset_passphrase(preset)
   {
   first_try = true;
   }

namespace UI {

/*************************************************
* The current pulse function                     *
*************************************************/
pulse_func pulse_f = 0;
void* pulse_f_data = 0;

/*************************************************
* Set the UI pulse function                      *
*************************************************/
void set_pulse(pulse_func p, void* p_data)
   {
   pulse_f = p;
   pulse_f_data = p_data;
   }

/*************************************************
* Call the UI pulse function                     *
*************************************************/
void pulse(Pulse_Type type)
   {
   if(pulse_f)
      pulse_f(type, pulse_f_data);
   }

}

}
