/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_CORE_H_
#define BOTAN_ASIO_STREAM_CORE_H_

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
      struct Buffer
         {
         Buffer() : dynamicBuffer(data_buffer) {}
         std::vector<uint8_t> data_buffer;
         boost::asio::dynamic_vector_buffer<
         uint8_t, typename decltype(data_buffer)::allocator_type>
         dynamicBuffer;
         };

      StreamCore()
         : m_input_buffer_space(17 * 1024, '\0'), // enough for a TLS Datagram
           input_buffer(boost::asio::buffer(m_input_buffer_space)) {}

      virtual ~StreamCore() = default;

      void tls_emit_data(const uint8_t data[], size_t size) override
         {
         auto buffer = m_send_buffer.dynamicBuffer.prepare(size);
         auto copySize =
            boost::asio::buffer_copy(buffer, boost::asio::buffer(data, size));
         m_send_buffer.dynamicBuffer.commit(copySize);
         }

      void tls_record_received(uint64_t, const uint8_t data[],
                               size_t size) override
         {
         // TODO: It would be nice to avoid this buffer copy. However, we need to deal with the case that the receive
         // buffer provided by the caller is smaller than the decrypted record.
         auto buffer = m_receive_buffer.dynamicBuffer.prepare(size);
         auto copySize =
            boost::asio::buffer_copy(buffer, boost::asio::buffer(data, size));
         m_receive_buffer.dynamicBuffer.commit(copySize);
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
         return m_receive_buffer.dynamicBuffer.size() > 0;
         }

      template <typename MutableBufferSequence>
      std::size_t copyReceivedData(MutableBufferSequence buffers)
         {
         const auto copiedBytes =
            boost::asio::buffer_copy(buffers, m_receive_buffer.dynamicBuffer.data());
         m_receive_buffer.dynamicBuffer.consume(copiedBytes);
         return copiedBytes;
         }

      bool hasDataToSend() const { return m_send_buffer.dynamicBuffer.size() > 0; }

      boost::asio::const_buffer sendBuffer() const
         {
         return m_send_buffer.dynamicBuffer.data();
         }

      void consumeSendBuffer(std::size_t bytesConsumed)
         {
         m_send_buffer.dynamicBuffer.consume(bytesConsumed);
         }

   private:
      // Buffer space used to read input intended for the engine.
      std::vector<uint8_t> m_input_buffer_space;
      Buffer               m_receive_buffer;
      Buffer               m_send_buffer;

   public:
      // A buffer that may be used to read input intended for the engine.
      const boost::asio::mutable_buffer input_buffer;
   };

}  // namespace TLS

}  // namespace Botan

#endif
