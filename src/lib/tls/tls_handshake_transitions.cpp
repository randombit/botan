/*
* TLS Handshake State Transitions
* (C) 2004-2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_transitions.h>

#include <botan/tls_exceptn.h>

#include <sstream>

namespace Botan::TLS {

namespace {

uint32_t bitmask_for_handshake_type(Handshake_Type type)
   {
   switch(type)
      {
      case Handshake_Type::HELLO_VERIFY_REQUEST:
         return (1 << 0);

      case Handshake_Type::HELLO_REQUEST:
         return (1 << 1);

      case Handshake_Type::CLIENT_HELLO:
         return (1 << 2);

      case Handshake_Type::SERVER_HELLO:
         return (1 << 3);

      case Handshake_Type::CERTIFICATE:
         return (1 << 4);

      case Handshake_Type::CERTIFICATE_URL:
         return (1 << 5);

      case Handshake_Type::CERTIFICATE_STATUS:
         return (1 << 6);

      case Handshake_Type::SERVER_KEX:
         return (1 << 7);

      case Handshake_Type::CERTIFICATE_REQUEST:
         return (1 << 8);

      case Handshake_Type::SERVER_HELLO_DONE:
         return (1 << 9);

      case Handshake_Type::CERTIFICATE_VERIFY:
         return (1 << 10);

      case Handshake_Type::CLIENT_KEX:
         return (1 << 11);

      case Handshake_Type::NEW_SESSION_TICKET:
         return (1 << 12);

      case Handshake_Type::HANDSHAKE_CCS:
         return (1 << 13);

      case Handshake_Type::FINISHED:
         return (1 << 14);

      case Handshake_Type::END_OF_EARLY_DATA:     // RFC 8446
         return (1 << 15);

      case Handshake_Type::ENCRYPTED_EXTENSIONS:  // RFC 8446
         return (1 << 16);

      case Handshake_Type::KEY_UPDATE:            // RFC 8446
         return (1 << 17);

      case Handshake_Type::HELLO_RETRY_REQUEST:   // RFC 8446
         return (1 << 18);

      // allow explicitly disabling new handshakes
      case Handshake_Type::HANDSHAKE_NONE:
         return 0;
      }

   throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                       "Unknown TLS handshake message type " +
                       std::to_string(static_cast<size_t>(type)));
   }

std::string handshake_mask_to_string(uint32_t mask, char combiner)
   {
   const Handshake_Type types[] = {
      Handshake_Type::HELLO_VERIFY_REQUEST,
      Handshake_Type::HELLO_REQUEST,
      Handshake_Type::CLIENT_HELLO,
      Handshake_Type::SERVER_HELLO,
      Handshake_Type::CERTIFICATE,
      Handshake_Type::CERTIFICATE_URL,
      Handshake_Type::CERTIFICATE_STATUS,
      Handshake_Type::SERVER_KEX,
      Handshake_Type::CERTIFICATE_REQUEST,
      Handshake_Type::SERVER_HELLO_DONE,
      Handshake_Type::CERTIFICATE_VERIFY,
      Handshake_Type::CLIENT_KEX,
      Handshake_Type::NEW_SESSION_TICKET,
      Handshake_Type::HANDSHAKE_CCS,
      Handshake_Type::FINISHED,
      Handshake_Type::END_OF_EARLY_DATA,
      Handshake_Type::ENCRYPTED_EXTENSIONS,
      Handshake_Type::KEY_UPDATE
      };

   std::ostringstream o;
   bool empty = true;

   for(auto&& t : types)
      {
      if(mask & bitmask_for_handshake_type(t))
         {
         if(!empty)
            { o << combiner; }
         o << handshake_type_to_string(t);
         empty = false;
         }
      }

   return o.str();
   }

}

bool Handshake_Transitions::received_handshake_msg(Handshake_Type msg_type) const
   {
   const uint32_t mask = bitmask_for_handshake_type(msg_type);

   return (m_hand_received_mask & mask) != 0;
   }

void Handshake_Transitions::confirm_transition_to(Handshake_Type msg_type)
   {
   const uint32_t mask = bitmask_for_handshake_type(msg_type);

   m_hand_received_mask |= mask;

   const bool ok = (m_hand_expecting_mask & mask) != 0; // overlap?

   if(!ok)
      {
      const uint32_t seen_so_far = m_hand_received_mask & ~mask;

      std::ostringstream msg;

      msg << "Unexpected state transition in handshake got a " << handshake_type_to_string(msg_type);

      if(m_hand_expecting_mask == 0)
         { msg << " not expecting messages"; }
      else
         { msg << " expected " << handshake_mask_to_string(m_hand_expecting_mask, '|'); }

      if(seen_so_far != 0)
         { msg << " seen " << handshake_mask_to_string(seen_so_far, '+'); }

      throw Unexpected_Message(msg.str());
      }

   /* We don't know what to expect next, so force a call to
      set_expected_next; if it doesn't happen, the next transition
      check will always fail which is what we want.
   */
   m_hand_expecting_mask = 0;
   }

void Handshake_Transitions::set_expected_next(Handshake_Type msg_type)
   {
   m_hand_expecting_mask |= bitmask_for_handshake_type(msg_type);
   }

void Handshake_Transitions::set_expected_next(const std::vector<Handshake_Type>& msg_types)
   {
   for (const auto type : msg_types)
      {
      set_expected_next(type);
      }
   }

bool Handshake_Transitions::change_cipher_spec_expected() const
   {
   return (bitmask_for_handshake_type(Handshake_Type::HANDSHAKE_CCS) & m_hand_expecting_mask) != 0;
   }

}
