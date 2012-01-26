/*
* Alert Message
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_alert.h>
#include <botan/exceptn.h>

namespace Botan {

namespace TLS {

Alert::Alert(const MemoryRegion<byte>& buf)
   {
   if(buf.size() != 2)
      throw Decoding_Error("Alert: Bad size " + to_string(buf.size()) +
                           " for alert message");

   if(buf[0] == 1)      fatal = false;
   else if(buf[0] == 2) fatal = true;
   else
      throw Decoding_Error("Alert: Bad code for alert level");

   const byte dc = buf[1];

   /*
   * This is allowed by the specification but is not allocated and we're
   * using it internally as a special 'no alert' type.
   */
   if(dc == 255)
      throw Decoding_Error("Alert: description code 255, rejecting");

   type_code = static_cast<Type>(dc);
   }

std::string Alert::type_string() const
   {
   return "";
   }


}

}
