/*
* TLS Callbacks
* (C) 2016 Matthias Gierlings
*     2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CALLBACKS_H__
#define BOTAN_TLS_CALLBACKS_H__

#include <botan/tls_session.h>
#include <botan/tls_alert.h>
namespace Botan {

namespace TLS {

class Handshake_Message;

/**
* Encapsulates the callbacks that a TLS channel will make which are due to
* channel specific operations.
*/
class BOTAN_DLL Callbacks
   {
   public:
       virtual ~Callbacks() {}

       /**
       * Mandatory callback: output function
       * The channel will call this with data which needs to be sent to the peer
       * (eg, over a socket or some other form of IPC). The array will be overwritten
       * when the function returns so a copy must be made if the data cannot be
       * sent immediately.
       */
       virtual void tls_emit_data(const uint8_t data[], size_t size) = 0;

       /**
       * Mandatory callback: process application data
       * Called when application data record is received from the peer.
       * Again the array is overwritten immediately after the function returns.
       * seq_no is the underlying TLS/DTLS record sequence number.
       */
       virtual void tls_record_received(u64bit seq_no, const uint8_t data[], size_t size) = 0;
     
       /**
       * Mandary callback: alert received
       * Called when an alert is received from the peer
       * If fatal, the connection is closing. If not fatal, the connection may
       * still be closing (depending on the error and the peer).
       */ 
       virtual void tls_alert(Alert alert) = 0;

       /**
       * Mandatory callback: session established
       * Called when a session is established. Throw an exception to abort
       * the connection. Return false to prevent the session from being cached.
       * Return true to cache the session in the configured session manager.
       */ 
       virtual bool tls_session_established(const Session& session) = 0;

       /**
       * Optional callback: inspect handshake message
       */       
       virtual void tls_inspect_handshake_msg(const Handshake_Message&) {}

       /**
       * Optional callback: debug logging. (not currently used)
       */       
       virtual bool tls_log_debug(const char*) { return false; }
   };

/**
* TLS::Callbacks using std::function for compatability with the old API signatures.
* This type is only provided for backward compatibility.
* New implementations should derive from TLS::Callbacks instead.
*/
class BOTAN_DLL Compat_Callbacks final : public Callbacks
   {
   public:
      typedef std::function<void (const byte[], size_t)> output_fn;
      typedef std::function<void (const byte[], size_t)> data_cb;
      typedef std::function<void (Alert, const byte[], size_t)> alert_cb;
      typedef std::function<bool (const Session&)> handshake_cb;
      typedef std::function<void (const Handshake_Message&)> handshake_msg_cb;

      /**
       * @param output_fn is called with data for the outbound socket
       *
       * @param app_data_cb is called when new application data is received
       *
       * @param alert_cb is called when a TLS alert is received
       *
       * @param handshake_cb is called when a handshake is completed
       */
       BOTAN_DEPRECATED("Use TLS::Callbacks (virtual interface).")
       Compat_Callbacks(output_fn out, data_cb app_data_cb, alert_cb alert_cb,
                        handshake_cb hs_cb, handshake_msg_cb hs_msg_cb = nullptr)
          : m_output_function(out), m_app_data_cb(app_data_cb),
            m_alert_cb(std::bind(alert_cb, std::placeholders::_1, nullptr, 0)),
            m_hs_cb(hs_cb), m_hs_msg_cb(hs_msg_cb) {}

       BOTAN_DEPRECATED("Use TLS::Callbacks (virtual interface).")
       Compat_Callbacks(output_fn out, data_cb app_data_cb,
                        std::function<void (Alert)> alert_cb,
                        handshake_cb hs_cb, handshake_msg_cb hs_msg_cb = nullptr)
          : m_output_function(out), m_app_data_cb(app_data_cb),
            m_alert_cb(alert_cb),
            m_hs_cb(hs_cb), m_hs_msg_cb(hs_msg_cb) {}

       void tls_emit_data(const byte data[], size_t size) override
          {
          BOTAN_ASSERT(m_output_function != nullptr,
                       "Invalid TLS output function callback.");
          m_output_function(data, size);
          }

       void tls_record_received(u64bit /*seq_no*/, const byte data[], size_t size) override
          {
          BOTAN_ASSERT(m_app_data_cb != nullptr,
                       "Invalid TLS app data callback.");
          m_app_data_cb(data, size);
          }

       void tls_alert(Alert alert) override
          {
          BOTAN_ASSERT(m_alert_cb != nullptr,
                       "Invalid TLS alert callback.");
          m_alert_cb(alert);
          }

       bool tls_session_established(const Session& session) override
          {
          BOTAN_ASSERT(m_hs_cb != nullptr,
                       "Invalid TLS handshake callback.");
          return m_hs_cb(session);
          }

       void tls_inspect_handshake_msg(const Handshake_Message& hmsg) override
          {
          // The handshake message callback is optional so we can
          // not assume it has been set.
          if(m_hs_msg_cb != nullptr) { m_hs_msg_cb(hmsg); }
          }

    private:
         const output_fn m_output_function;
         const data_cb m_app_data_cb;
         const std::function<void (Alert)> m_alert_cb;
         const handshake_cb m_hs_cb;
         const handshake_msg_cb m_hs_msg_cb;
   };

}

}

#endif
