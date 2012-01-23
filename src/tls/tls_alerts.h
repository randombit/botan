/*
* Alert Message
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_ALERT_H__
#define BOTAN_TLS_ALERT_H__

#include <botan/tls_exceptn.h>

namespace Botan {

namespace TLS {

/**
* SSL/TLS Alert Message
*/
class Alert
   {
   public:
      /**
      * @return if this alert is a fatal one or not
      */
      bool is_fatal() const { return fatal; }

      /**
      * @return type of alert
      */
      Alert_Type type() const { return type_code; }

      /**
      * Deserialize an Alert message
      * @param buf the serialized alert
      */
      Alert(const MemoryRegion<byte>& buf)
         {
         if(buf.size() != 2)
            throw Decoding_Error("Alert: Bad size " + to_string(buf.size()) +
                                 " for alert message");

         if(buf[0] == 1)      fatal = false;
         else if(buf[0] == 2) fatal = true;
         else
            throw Decoding_Error("Alert: Bad code for alert level");

         const byte dc = buf[1];

         if(dc == 255)
            throw Decoding_Error("Alert: description code 255, rejecting");

         type_code = static_cast<Alert_Type>(dc);
         }
   private:
      bool fatal;
      Alert_Type type_code;
   };

}

}

#endif
