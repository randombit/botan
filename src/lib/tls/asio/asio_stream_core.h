/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_CORE_H_
#define BOTAN_ASIO_STREAM_CORE_H_

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <boost/version.hpp>
#if BOOST_VERSION > 106600

#include <boost/beast/core/flat_buffer.hpp>
#include <botan/internal/asio_includes.h>
#include <botan/tls_callbacks.h>
#include <mutex>
#include <vector>

namespace Botan {

namespace TLS {

/**
 * Contains the buffers for reading/sending, and the needed botan callbacks
 */
struct StreamCore : public Botan::TLS::Callbacks
   {
      StreamCore()
         : m_input_buffer_space(17 * 1024, '\0'), // enough for a TLS Datagram
           input_buffer(m_input_buffer_space.data(), m_input_buffer_space.size()) {}

      virtual ~StreamCore() = default;

      void tls_emit_data(const uint8_t data[], size_t size) override
         {
         m_send_buffer.commit(
            boost::asio::buffer_copy(m_send_buffer.prepare(size), boost::asio::buffer(data, size)));
         }

      void tls_record_received(uint64_t, const uint8_t data[],
                               size_t size) override
         {
         // TODO: It would be nice to avoid this buffer copy. However, we need to deal with the case that the receive
         // buffer provided by the caller is smaller than the decrypted record.
         auto buffer = m_receive_buffer.prepare(size);
         auto copySize =
            boost::asio::buffer_copy(buffer, boost::asio::const_buffer(data, size));
         m_receive_buffer.commit(copySize);
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         if(alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
            {
            // TODO
            }
         }

      std::chrono::milliseconds
      tls_verify_cert_chain_ocsp_timeout() const override
         {
         return std::chrono::milliseconds(1000);
         }

      bool tls_session_established(const Botan::TLS::Session&) override
         {
         return true;
         }

      bool hasReceivedData() const
         {
         return m_receive_buffer.size() > 0;
         }

      template <typename MutableBufferSequence>
      std::size_t copyReceivedData(MutableBufferSequence buffers)
         {
         const auto copiedBytes =
            boost::asio::buffer_copy(buffers, m_receive_buffer.data());
         m_receive_buffer.consume(copiedBytes);
         return copiedBytes;
         }

      bool hasDataToSend() const { return m_send_buffer.size() > 0; }

      boost::asio::const_buffer sendBuffer() const
         {
         return m_send_buffer.data();
         }

      void consumeSendBuffer(std::size_t bytesConsumed)
         {
         m_send_buffer.consume(bytesConsumed);
         }

      void clearSendBuffer()
         {
         consumeSendBuffer(m_send_buffer.size());
         }

   private:
      // Buffer space used to read input intended for the engine.
      std::vector<uint8_t>      m_input_buffer_space;
      boost::beast::flat_buffer m_receive_buffer;
      boost::beast::flat_buffer m_send_buffer;

   public:
      // A buffer that may be used to read input intended for the engine.
      const boost::asio::mutable_buffer input_buffer;
   };

}  // namespace TLS

}  // namespace Botan

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO
#endif // BOTAN_ASIO_STREAM_CORE_H_
