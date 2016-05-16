/*
* TLS Callbacks
* (C) 2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CALLBACKS_H__
#define BOTAN_TLS_CALLBACKS_H__

#include <botan/tls_session.h>
#include <botan/tls_alert.h>
namespace Botan {

namespace TLS {

class Handshake_State;
class Handshake_Message;

/**
* Virtual Interface for TLS-Channel related callback handling. The default
* implementations involving std::function are only provided for compatibility
* purposes. New implementations should override the virtual member methods
* out_fn(), app_data(), alert(), handshake() and handshake_msg() instead.
*
*/
class BOTAN_DLL Callbacks
   {
   public:
      typedef std::function<void (const byte[], size_t)> output_fn;
      typedef std::function<void (const byte[], size_t)> data_cb;
      typedef std::function<void (Alert)> alert_cb;
      typedef std::function<bool (const Session&)> handshake_cb;
      typedef std::function<void (const Handshake_Message&)> handshake_msg_cb;

      /**
       * DEPRECATED: This constructor is only provided for backward
       * compatibility. New implementations should override the
       * virtual member methods out_fn(), app_data(), alert(),
       * handshake() and handshake_msg() and use the default constructor
       * Callbacks().
       *
       * Encapsulates a set of callback functions required by a TLS Channel.
       * @param output_fn is called with data for the outbound socket
       *
       * @param app_data_cb is called when new application data is received
       *
       * @param alert_cb is called when a TLS alert is received
       *
       * @param handshake_cb is called when a handshake is completed
       */
       BOTAN_DEPRECATED("Use TLS::Callbacks() (virtual interface).")
       Callbacks(output_fn out, data_cb app_data_cb, alert_cb alert_cb,
                 handshake_cb hs_cb, handshake_msg_cb hs_msg_cb = nullptr)
          : m_output_function(out), m_app_data_cb(app_data_cb),
            m_alert_cb(alert_cb), m_hs_cb(hs_cb), m_hs_msg_cb(hs_msg_cb) {}

       Callbacks()
          : m_output_function(nullptr), m_app_data_cb(nullptr),
            m_alert_cb(nullptr), m_hs_cb(nullptr), m_hs_msg_cb(nullptr) {}


       virtual ~Callbacks() {}

       virtual void out_fn(const byte data[], size_t size) const
          {
          BOTAN_ASSERT(m_output_function != nullptr,
                       "Invalid TLS output function callback.");
          m_output_function(data, size);
          }

       virtual void app_data(const byte data[], size_t size) const
          {
          BOTAN_ASSERT(m_app_data_cb != nullptr,
                       "Invalid TLS app data callback.");
          m_app_data_cb(data, size);
          }

       virtual void alert(Alert alert) const
          {
          BOTAN_ASSERT(m_alert_cb != nullptr,
                       "Invalid TLS alert callback.");
          m_alert_cb(alert);
          }

       virtual bool handshake(const Session& session) const
          {
          BOTAN_ASSERT(m_hs_cb != nullptr,
                       "Invalid TLS handshake callback.");
          return m_hs_cb(session);
          }

       virtual void handshake_msg(const Handshake_Message& hmsg) const
          {
          // The handshake message callback is optional so we can
          // not assume it has been set.
          if(m_hs_msg_cb != nullptr) { m_hs_msg_cb(hmsg); }
          }

    private:
         const output_fn m_output_function;
         const data_cb m_app_data_cb;
         const alert_cb m_alert_cb;
         const handshake_cb m_hs_cb;
         const handshake_msg_cb m_hs_msg_cb;
   };

}

}

#endif
