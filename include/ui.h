/*************************************************
* User Interface Header File                     *
* (C) 1999-2007 The Botan Project                *
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

}

#endif
