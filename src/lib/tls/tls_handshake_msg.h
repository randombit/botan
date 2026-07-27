/*
* TLS Handshake Message
* (C) 2012 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_MSG_H_
#define BOTAN_TLS_HANDSHAKE_MSG_H_

#include <botan/tls_magic.h>
#include <string>
#include <vector>

namespace Botan::TLS {

class Handshake_IO;
class Handshake_Hash;

/**
* TLS Handshake Message Base Class
*/
class BOTAN_PUBLIC_API(2, 0) Handshake_Message {
   public:
      /**
      * Return a free-form string describing this message type
      *
      * @return string representation of this message type
      */
      std::string type_string() const;

      /**
      * Return the TLS handshake type code
      * @return the message type
      */
      virtual Handshake_Type type() const = 0;

      /**
      * Return the wire encoding of the message type code
      *
      * @note This is usually equal to `type` with the exception of
      * a TLS 1.3 Helloy Retry Request.
      *
      * @return the wire representation of the message's type
      */
      virtual Handshake_Type wire_type() const { return type(); }

      /**
      * Serialize this handshake message
      */
      virtual std::vector<uint8_t> serialize() const = 0;

      virtual ~Handshake_Message() = default;
      Handshake_Message() = default;
      Handshake_Message(const Handshake_Message&) = delete;
      Handshake_Message(Handshake_Message&&) = default;
      Handshake_Message& operator=(const Handshake_Message&) = delete;
      Handshake_Message& operator=(Handshake_Message&&) = default;
};

}  // namespace Botan::TLS

#endif
