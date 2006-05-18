/*************************************************
* User Interface Header File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_UI_H__
#define BOTAN_UI_H__

#include <string>

namespace Botan {

/*************************************************
* User Interface                                 *
*************************************************/
class User_Interface
   {
   public:
      enum UI_Result { OK, CANCEL_ACTION };

      virtual std::string get_passphrase(const std::string&,
                                         const std::string&,
                                         UI_Result&) const;
      User_Interface(const std::string& = "");
      virtual ~User_Interface() {}
   protected:
      const std::string preset_passphrase;
      mutable bool first_try;
   };

namespace UI {

/*************************************************
* Pulse Function                                 *
*************************************************/
enum Pulse_Type {
   GENERAL_PULSE,

   PIPE_WRITE,

   PRIME_SEARCHING,
   PRIME_SIEVING,
   PRIME_PASSED_SIEVE,
   PRIME_TESTING,
   PRIME_FOUND
};
typedef void (*pulse_func)(Pulse_Type, void*);

/*************************************************
* Set the UI pulse function                      *
*************************************************/
void set_pulse(pulse_func, void* = 0);

/*************************************************
* Call the UI pulse function                     *
*************************************************/
void pulse(Pulse_Type = GENERAL_PULSE);

}

}

#endif
