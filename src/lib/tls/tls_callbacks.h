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
       virtual ~Callbacks();

       /**
       * Mandatory callback: output function
       * The channel will call this with data which needs to be sent to the peer
       * (eg, over a socket or some other form of IPC). The array will be overwritten
       * when the function returns so a copy must be made if the data cannot be
       * sent immediately.
       *
       * @param data the vector of data to send
       *
       * @param size the number of bytes to send
       */
       virtual void tls_emit_data(const uint8_t data[], size_t size) = 0;

       /**
       * Mandatory callback: process application data
       * Called when application data record is received from the peer.
       * Again the array is overwritten immediately after the function returns.
       *
       * @param seq_no the underlying TLS/DTLS record sequence number
       *
       * @param data the vector containing the received record
       *
       * @param size the length of the received record, in bytes
       */
       virtual void tls_record_received(u64bit seq_no, const uint8_t data[], size_t size) = 0;

       /**
       * Mandary callback: alert received
       * Called when an alert is received from the peer
       * If fatal, the connection is closing. If not fatal, the connection may
       * still be closing (depending on the error and the peer).
       *
       * @param alert the source of the alert
       */
       virtual void tls_alert(Alert alert) = 0;

       /**
       * Mandatory callback: session established
       * Called when a session is established. Throw an exception to abort
       * the connection.
       *
       * @param session the session descriptor
       *
       * @return return false to prevent the session from being cached,
       * return true to cache the session in the configured session manager
       */
       virtual bool tls_session_established(const Session& session) = 0;

       /**
       * Optional callback: inspect handshake message
       * Throw an exception to abort the handshake.
       * Default simply ignores the message.
       *
       * @param message the handshake message
       */
       virtual void tls_inspect_handshake_msg(const Handshake_Message& message);

       /**
       * Optional callback for server: choose ALPN protocol
       * ALPN (RFC 7301) works by the client sending a list of application
       * protocols it is willing to negotiate. The server then selects which
       * protocol to use, which is not necessarily even on the list that
       * the client sent.
       *
       * @param client_protos the vector of protocols the client is willing to negotiate
       *
       * @return the protocol selected by the server, which need not be on the
       * list that the client sent; if this is the empty string, the server ignores the
       * client ALPN extension. Default return value is empty string.
       */
       virtual std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos);

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
      typedef std::function<std::string (std::vector<std::string>)> next_protocol_fn;

      /**
       * @param output_fn is called with data for the outbound socket
       *
       * @param app_data_cb is called when new application data is received
       *
       * @param alert_cb is called when a TLS alert is received
       *
       * @param hs_cb is called when a handshake is completed
       *
       * @param hs_msg_cb is called for each handshake message received
       *
       * @param next_proto is called with ALPN protocol data sent by the client
       */
       BOTAN_DEPRECATED("Use TLS::Callbacks (virtual interface).")
       Compat_Callbacks(output_fn output_fn, data_cb app_data_cb, alert_cb alert_cb,
                        handshake_cb hs_cb, handshake_msg_cb hs_msg_cb = nullptr,
                        next_protocol_fn next_proto = nullptr)
          : m_output_function(output_fn), m_app_data_cb(app_data_cb),
            m_alert_cb(std::bind(alert_cb, std::placeholders::_1, nullptr, 0)),
            m_hs_cb(hs_cb), m_hs_msg_cb(hs_msg_cb), m_next_proto(next_proto) {}

       BOTAN_DEPRECATED("Use TLS::Callbacks (virtual interface).")
       Compat_Callbacks(output_fn output_fn, data_cb app_data_cb,
                        std::function<void (Alert)> alert_cb,
                        handshake_cb hs_cb,
                        handshake_msg_cb hs_msg_cb = nullptr,
                        next_protocol_fn next_proto = nullptr)
          : m_output_function(output_fn), m_app_data_cb(app_data_cb),
            m_alert_cb(alert_cb),
            m_hs_cb(hs_cb), m_hs_msg_cb(hs_msg_cb), m_next_proto(next_proto) {}

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

       std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override
          {
          if(m_next_proto != nullptr) { return m_next_proto(client_protos); }
          return "";
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
         const next_protocol_fn m_next_proto;
   };

}

}

#endif
