/*
* Shared helpers for TLS ASIO Datagram tests
* (C) 2026 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_ASIO_DATAGRAM_HELPERS_H_
#define BOTAN_TEST_ASIO_DATAGRAM_HELPERS_H_

#include "../cli/tls_helpers.h"
#include "tests.h"

#include <botan/asio_datagram.h>
#include <botan/auto_rng.h>
#include <botan/rng.h>
#include <botan/tls_session_manager_noop.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <chrono>
#include <deque>
#include <functional>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace Botan_Tests::Asio_Datagram_Test {

namespace net = boost::asio;
using error_code = boost::system::error_code;
using udp = net::ip::udp;

inline std::vector<uint8_t> vec(std::string_view s) {
   return {s.begin(), s.end()};
}

class ControlledDatagramLayer {
   public:
      using executor_type = net::io_context::executor_type;
      using lowest_layer_type = ControlledDatagramLayer;

      enum class Direction : uint8_t { ClientToServer, ServerToClient };

      struct Control {
            bool drop_first_client_to_server = false;
            bool drop_first_server_to_client = false;
            bool reorder_first_server_flight = false;
            std::optional<Direction> drop_first_final_flight;
            bool final_flight_dropped = false;
            size_t dropped_ccs = 0;
            size_t dropped_finished = 0;
            size_t handshake_records_sent = 0;
            std::optional<Direction> hold_next_send;
            size_t hold_after_sends = 0;
            size_t held_sends = 0;
            size_t aborted_sends = 0;
            size_t held_send_completions = 0;
            std::function<void()> on_send_held;
            size_t client_to_server_sent = 0;
            size_t server_to_client_sent = 0;
            size_t dropped = 0;
            size_t reordered = 0;
            std::optional<std::vector<uint8_t>> held_server_datagram;
      };

   private:
      class State {
         public:
            State(net::io_context& io_context, Direction direction, std::shared_ptr<Control> layer_control) :
                  m_io(&io_context), m_dir(direction), m_control(std::move(layer_control)) {}

         private:
            friend class ControlledDatagramLayer;
            net::io_context* m_io;
            Direction m_dir;
            std::weak_ptr<State> m_peer;
            std::shared_ptr<Control> m_control;
            std::deque<std::vector<uint8_t>> m_incoming;
            boost::asio::mutable_buffer m_pending_buffer;
            std::function<void(error_code, size_t)> m_pending_receive;
            std::function<void(error_code, size_t)> m_pending_send;
            size_t m_pending_send_size = 0;
            bool m_closed = false;
      };

   public:
      explicit ControlledDatagramLayer(std::shared_ptr<State> state) : m_state(std::move(state)) {}

      executor_type get_executor() noexcept { return m_state->m_io->get_executor(); }

      ControlledDatagramLayer& lowest_layer() { return *this; }

      const ControlledDatagramLayer& lowest_layer() const { return *this; }

      udp::endpoint remote_endpoint() const {
         return udp::endpoint(net::ip::address_v4::loopback(),
                              m_state->m_dir == Direction::ClientToServer ? 4433 : 4434);
      }

      void cancel(error_code& ec) {
         ec.clear();
         cancel_receive(m_state);
         cancel_send(m_state);
      }

      void release_held_send() {
         if(auto handler = std::exchange(m_state->m_pending_send, {})) {
            net::post(get_executor(),
                      [handler = std::move(handler),
                       control = m_state->m_control,
                       sent = m_state->m_pending_send_size]() mutable {
                         ++control->held_send_completions;
                         handler({}, sent);
                      });
         }
      }

      void close() {
         m_state->m_closed = true;
         error_code ignored;
         cancel(ignored);
      }

      size_t send(const net::const_buffer& buffer, [[maybe_unused]] int flags, error_code& ec) {
         if(m_state->m_closed) {
            ec = net::error::operation_aborted;
            return 0;
         }

         ec.clear();
         std::vector<uint8_t> datagram(static_cast<const uint8_t*>(buffer.data()),
                                       static_cast<const uint8_t*>(buffer.data()) + buffer.size());

         if(m_state->m_dir == Direction::ClientToServer) {
            ++m_state->m_control->client_to_server_sent;
         } else {
            ++m_state->m_control->server_to_client_sent;
         }

         // Inspect only plaintext record headers, never the encrypted Finished body.
         bool contains_ccs = false;
         bool contains_finished = false;
         for(size_t offset = 0; offset + 13 <= datagram.size();) {
            const auto length = (static_cast<size_t>(datagram[offset + 11]) << 8) | datagram[offset + 12];
            if(length > datagram.size() - offset - 13) {
               break;
            }
            const auto type = datagram[offset];
            const auto epoch = (static_cast<size_t>(datagram[offset + 3]) << 8) | datagram[offset + 4];
            contains_ccs |= type == 20;
            contains_finished |= type == 22 && epoch == 1;
            if(type == 20 || type == 22) {
               ++m_state->m_control->handshake_records_sent;
            }
            offset += 13 + length;
         }
         auto& control = *m_state->m_control;
         if(control.drop_first_final_flight == m_state->m_dir && !control.final_flight_dropped &&
            (contains_ccs || contains_finished)) {
            if(contains_ccs) {
               ++control.dropped_ccs;
            }
            if(contains_finished) {
               ++control.dropped_finished;
            }
            control.final_flight_dropped = contains_finished;
            ++control.dropped;
            return buffer.size();
         }

         if(m_state->m_dir == Direction::ClientToServer) {
            if(m_state->m_control->drop_first_client_to_server && m_state->m_control->client_to_server_sent == 1) {
               ++m_state->m_control->dropped;
               return buffer.size();
            }
         }

         if(m_state->m_dir == Direction::ServerToClient) {
            if(m_state->m_control->drop_first_server_to_client && m_state->m_control->server_to_client_sent == 1) {
               ++m_state->m_control->dropped;
               return buffer.size();
            }

            if(m_state->m_control->reorder_first_server_flight && m_state->m_control->reordered == 0) {
               if(!m_state->m_control->held_server_datagram) {
                  m_state->m_control->held_server_datagram = std::move(datagram);
                  return buffer.size();
               }

               deliver(std::move(datagram));
               auto held = std::move(*m_state->m_control->held_server_datagram);
               m_state->m_control->held_server_datagram.reset();
               ++m_state->m_control->reordered;
               deliver(std::move(held));
               return buffer.size();
            }
         }

         deliver(std::move(datagram));
         return buffer.size();
      }

      template <typename Handler>
      void async_send(const net::const_buffer& buffer, Handler&& handler) {
         error_code ec;
         const auto sent = send(buffer, 0, ec);
         const auto sent_count = m_state->m_dir == Direction::ClientToServer
                                    ? m_state->m_control->client_to_server_sent
                                    : m_state->m_control->server_to_client_sent;
         if(!ec && m_state->m_control->hold_next_send == m_state->m_dir &&
            sent_count > m_state->m_control->hold_after_sends) {
            m_state->m_control->hold_next_send.reset();
            ++m_state->m_control->held_sends;
            auto slot = net::get_associated_cancellation_slot(handler);
            m_state->m_pending_send_size = sent;
            m_state->m_pending_send = [handler = std::forward<Handler>(handler), slot](error_code send_ec,
                                                                                       size_t n) mutable {
               slot.clear();
               std::move(handler)(send_ec, n);
            };
            if(slot.is_connected()) {
               slot.assign([weak = std::weak_ptr(m_state)](net::cancellation_type_t type) {
                  if((type & net::cancellation_type::terminal) != net::cancellation_type::none) {
                     if(auto state = weak.lock()) {
                        cancel_send(state);
                     }
                  }
               });
            }
            net::post(get_executor(), [control = m_state->m_control] {
               if(control->on_send_held) {
                  control->on_send_held();
               }
            });
            return;
         }
         net::post(get_executor(),
                   [handler = std::forward<Handler>(handler), ec, sent]() mutable { handler(ec, sent); });
      }

      size_t receive(const net::mutable_buffer& buffer, [[maybe_unused]] int flags, error_code& ec) {
         if(m_state->m_closed) {
            ec = net::error::operation_aborted;
            return 0;
         }

         if(m_state->m_incoming.empty()) {
            ec = net::error::would_block;
            return 0;
         }

         ec.clear();
         const auto copied = net::buffer_copy(buffer, net::buffer(m_state->m_incoming.front()));
         m_state->m_incoming.pop_front();
         return copied;
      }

      template <typename Handler>
      void async_receive(const net::mutable_buffer& buffer, Handler&& handler) {
         error_code ec;
         const auto received = receive(buffer, 0, ec);
         if(!ec || ec != net::error::would_block) {
            net::post(get_executor(),
                      [handler = std::forward<Handler>(handler), ec, received]() mutable { handler(ec, received); });
            return;
         }

         m_state->m_pending_buffer = buffer;
         auto slot = net::get_associated_cancellation_slot(handler);
         m_state->m_pending_receive = [handler = std::forward<Handler>(handler), slot](error_code receive_ec,
                                                                                       size_t n) mutable {
            slot.clear();
            std::move(handler)(receive_ec, n);
         };
         if(slot.is_connected()) {
            slot.assign([weak = std::weak_ptr(m_state)](net::cancellation_type_t type) {
               if((type & net::cancellation_type::terminal) != net::cancellation_type::none) {
                  if(auto state = weak.lock()) {
                     cancel_receive(state);
                  }
               }
            });
         }
      }

      static std::pair<ControlledDatagramLayer, ControlledDatagramLayer> make_pair(
         net::io_context& io, const std::shared_ptr<Control>& control) {
         auto client = std::make_shared<State>(io, Direction::ClientToServer, control);
         auto server = std::make_shared<State>(io, Direction::ServerToClient, control);
         client->m_peer = server;
         server->m_peer = client;
         return {ControlledDatagramLayer(client), ControlledDatagramLayer(server)};
      }

   private:
      static void cancel_receive(const std::shared_ptr<State>& state) {
         if(auto handler = std::exchange(state->m_pending_receive, {})) {
            net::post(state->m_io->get_executor(),
                      [handler = std::move(handler)]() mutable { handler(net::error::operation_aborted, 0); });
         }
      }

      static void cancel_send(const std::shared_ptr<State>& state) {
         if(auto handler = std::exchange(state->m_pending_send, {})) {
            ++state->m_control->aborted_sends;
            net::post(state->m_io->get_executor(),
                      [handler = std::move(handler), control = state->m_control]() mutable {
                         ++control->held_send_completions;
                         handler(net::error::operation_aborted, 0);
                      });
         }
      }

      void deliver(std::vector<uint8_t> datagram) {
         auto peer = m_state->m_peer.lock();
         if(!peer || peer->m_closed) {
            return;
         }

         if(peer->m_pending_receive) {
            auto handler = std::exchange(peer->m_pending_receive, {});
            const auto copied = net::buffer_copy(peer->m_pending_buffer, net::buffer(datagram));
            net::post(peer->m_io->get_executor(),
                      [handler = std::move(handler), copied]() mutable { handler({}, copied); });
         } else {
            peer->m_incoming.emplace_back(std::move(datagram));
         }
      }

      std::shared_ptr<State> m_state;
};

class TestCredentials final : public Basic_Credentials_Manager {
   public:
      using Basic_Credentials_Manager::Basic_Credentials_Manager;

      Botan::secure_vector<uint8_t> dtls_cookie_secret() override { return Botan::secure_vector<uint8_t>(32, 0x42); }
};

class FastDatagramPolicy : public Botan::TLS::Datagram_Policy {
   public:
      size_t dtls_initial_timeout() const override { return 10; }

      size_t dtls_maximum_timeout() const override { return 40; }
};

inline std::shared_ptr<Botan::TLS::Context> get_context() {
   return std::make_shared<Botan::TLS::Context>(std::make_shared<Botan::Credentials_Manager>(),
                                                std::make_shared<Botan::Null_RNG>(),
                                                std::make_shared<Botan::TLS::Session_Manager_Noop>(),
                                                std::make_shared<Botan::TLS::Datagram_Policy>());
}

inline std::string server_cert() {
   return Test::data_file("x509/certstor/cert1.crt");
}

inline std::string server_key() {
   return Test::data_file("x509/certstor/key01.pem");
}

inline void accept_all(const std::vector<Botan::X509_Certificate>& /*cert*/,
                       const std::vector<std::optional<Botan::OCSP::Response>>& /*ocsp*/,
                       const std::vector<Botan::Certificate_Store*>& /*trusted*/,
                       Botan::Usage_Type /*usage*/,
                       std::string_view /*hostname*/,
                       const Botan::TLS::Policy& /*policy*/) {}

inline std::shared_ptr<Botan::TLS::Context> get_real_context(
   std::shared_ptr<Botan::Credentials_Manager> credentials_manager,
   std::shared_ptr<const Botan::TLS::Policy> policy = std::make_shared<FastDatagramPolicy>()) {
   return std::make_shared<Botan::TLS::Context>(std::move(credentials_manager),
                                                std::make_shared<Botan::AutoSeeded_RNG>(),
                                                std::make_shared<Botan::TLS::Session_Manager_Noop>(),
                                                std::move(policy),
                                                Botan::TLS::Server_Information("localhost", 443));
}

template <typename Done, typename OnTimeout>
void run_until_or_fail(
   net::io_context& io, Test::Result& result, Done done, OnTimeout on_timeout, std::string_view failure) {
   auto timeout = net::steady_timer(io);
   bool timed_out = false;
   timeout.expires_after(std::chrono::seconds(5));
   timeout.async_wait([&](const error_code& ec) {
      if(!ec && !done()) {
         timed_out = true;
         result.test_failure(failure);
         on_timeout();
      }
   });

   while(!done() && !timed_out) {
      io.run_one_for(std::chrono::milliseconds(100));
      if(io.stopped() && !done()) {
         io.restart();
      }
   }

   // Give cancellation completions a bounded chance to drain after a failure.
   const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
   while(!done() && std::chrono::steady_clock::now() < drain_deadline) {
      io.restart();
      io.run_one_for(std::chrono::milliseconds(10));
   }

   timeout.cancel();
   io.run_for(std::chrono::milliseconds(1));
   io.restart();
}

class Completion {
   public:
      size_t calls() const { return m_calls; }

      size_t bytes() const { return m_bytes; }

      const error_code& error() const { return m_ec; }

      auto handler() {
         return [this](error_code error, size_t size = 0) {
            ++m_calls;
            m_ec = error;
            m_bytes = size;
         };
      }

   private:
      size_t m_calls = 0;
      size_t m_bytes = 0;
      error_code m_ec;
};

template <typename DatagramT>
void close_pair(DatagramT& client, DatagramT& server) {
   client.lowest_layer().close();
   server.lowest_layer().close();
}

template <typename DatagramT>
std::pair<error_code, error_code> run_handshake_pair(
   net::io_context& io, DatagramT& client, DatagramT& server, Test::Result& result, std::string_view timeout_message) {
   Completion client_handshake;
   Completion server_handshake;
   server.async_handshake(Botan::TLS::Connection_Side::Server, server_handshake.handler());
   client.async_handshake(Botan::TLS::Connection_Side::Client, client_handshake.handler());
   run_until_or_fail(
      io,
      result,
      [&] { return client_handshake.calls() > 0 && server_handshake.calls() > 0; },
      [&] { close_pair(client, server); },
      timeout_message);
   return {client_handshake.error(), server_handshake.error()};
}

inline std::pair<udp::socket, udp::socket> make_udp_pair(net::io_context& io) {
   udp::socket client(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   udp::socket server(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   client.connect(server.local_endpoint());
   server.connect(client.local_endpoint());
   return {std::move(client), std::move(server)};
}

template <typename Layer>
auto make_real_datagram_pair(std::pair<Layer, Layer> layers) {
   auto client_context = get_real_context(std::make_shared<Basic_Credentials_Manager>(true, ""));
   client_context->set_verify_callback(accept_all);
   auto server_context = get_real_context(std::make_shared<TestCredentials>(server_cert(), server_key()));
   return std::pair{Botan::TLS::Datagram<Layer>(std::move(client_context), std::move(layers.first)),
                    Botan::TLS::Datagram<Layer>(std::move(server_context), std::move(layers.second))};
}

std::vector<Test::Result> run_asio_datagram_integration_tests();

}  // namespace Botan_Tests::Asio_Datagram_Test

#endif
