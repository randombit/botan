/*
* TLS Handshake State Transitions
* (C) 2004-2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_TRANSITIONS_H_
#define BOTAN_TLS_HANDSHAKE_TRANSITIONS_H_

#include <vector>

#include <botan/tls_magic.h>

namespace Botan::TLS {

/**
 * Manages the expectations for incoming handshake messages in both TLS 1.2 and 1.3.
 * This does not bear any knowledge about the actual state machine but is a mere
 * helper to implement state transition validation.
 */
class BOTAN_TEST_API Handshake_Transitions {
   public:
      /**
       * Return true iff we have received a particular message already
       * @param msg_type the message type
       */
      bool received_handshake_msg(Handshake_Type msg_type) const;

      /**
       * Confirm that we were expecting this message type
       * @param msg_type the message type
       */
      void confirm_transition_to(Handshake_Type msg_type);

      /**
       * Record that we are expecting a particular message type next
       * @param msg_type the message type
       */
      void set_expected_next(Handshake_Type msg_type);

      /**
       * Record that we are expecting one of the enumerated message types next.
       * Note that receiving any of the expected messages in `confirm_transition_to`
       * resets _all_ the expectations.
       *
       * @param msg_types the message types
       */
      void set_expected_next(const std::vector<Handshake_Type>& msg_types);

      /**
       * Check whether a Change Cipher Spec must be expected
       */
      bool change_cipher_spec_expected() const;

   private:
      uint32_t m_hand_expecting_mask = 0;
      uint32_t m_hand_received_mask = 0;
};

}  // namespace Botan::TLS

#endif
