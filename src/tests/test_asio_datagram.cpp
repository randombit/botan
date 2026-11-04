/*
* TLS ASIO Datagram Integration Tests
* (C) 2026 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_12) && defined(BOTAN_HAS_AUTO_SEEDING_RNG) && defined(BOTAN_HAS_TLS_ASIO_STREAM)
   #include <botan/asio_compat.h>
   #if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_DATAGRAM_VERSION)
      #include "test_asio_datagram_helpers.h"
      #include <botan/tls_session_manager_memory.h>
      #include <array>
      #include <boost/asio/bind_cancellation_slot.hpp>
      #include <boost/asio/cancellation_signal.hpp>

namespace Botan_Tests::Asio_Datagram_Test {

namespace {

class NoRetransmissionsPolicy final : public FastDatagramPolicy {
   public:
      std::optional<size_t> dtls_maximum_retransmissions() const override { return 0; }
};

class SessionCallbacks final : public Botan::TLS::DatagramCallbacks {
   public:
      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         Botan::TLS::DatagramCallbacks::tls_session_established(session);
         ++m_established_calls;
         m_resumed = session.was_resumption();
      }

      size_t established_calls() const { return m_established_calls; }

      std::optional<bool> resumed() const { return m_resumed; }

   private:
      size_t m_established_calls = 0;
      std::optional<bool> m_resumed;
};

std::shared_ptr<Botan::TLS::Context> get_resumable_context(std::shared_ptr<Botan::Credentials_Manager> credentials) {
   auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
   return std::make_shared<Botan::TLS::Context>(std::move(credentials),
                                                rng,
                                                std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng),
                                                std::make_shared<FastDatagramPolicy>(),
                                                Botan::TLS::Server_Information("localhost", 443));
}

void check_final_flight_exchange(Test::Result& result,
                                 const std::shared_ptr<Botan::TLS::Context>& client_context,
                                 const std::shared_ptr<Botan::TLS::Context>& server_context,
                                 const std::shared_ptr<ControlledDatagramLayer::Control>& control,
                                 bool expect_resumption) {
   net::io_context io;
   auto [client_layer, server_layer] = ControlledDatagramLayer::make_pair(io, control);
   auto client_callbacks = std::make_shared<SessionCallbacks>();
   auto server_callbacks = std::make_shared<SessionCallbacks>();
   Botan::TLS::Datagram<ControlledDatagramLayer> client(client_context, client_callbacks, {}, std::move(client_layer));
   Botan::TLS::Datagram<ControlledDatagramLayer> server(server_context, server_callbacks, {}, std::move(server_layer));
   const auto client_payload = vec("client application datagram");
   const auto server_payload = vec("server application datagram");
   std::vector<uint8_t> client_buffer(server_payload.size());
   std::vector<uint8_t> server_buffer(client_payload.size());
   size_t client_handshakes = 0;
   size_t server_handshakes = 0;
   size_t client_sends = 0;
   size_t server_sends = 0;
   size_t client_receives = 0;
   size_t server_receives = 0;
   bool sends_started = false;
   bool failed = false;
   auto cancel_pair = [&] {
      client.cancel();
      server.cancel();
      client.lowest_layer().close();
      server.lowest_layer().close();
   };
   auto start_sends = [&] {
      if(client_handshakes == 1 && server_handshakes == 1 && !sends_started && !failed) {
         sends_started = true;
         client.async_send(net::buffer(client_payload), [&](error_code ec, size_t n) {
            ++client_sends;
            result.test_is_true("client application send succeeds", !ec);
            result.test_sz_eq("client application send size", n, client_payload.size());
         });
         server.async_send(net::buffer(server_payload), [&](error_code ec, size_t n) {
            ++server_sends;
            result.test_is_true("server application send succeeds", !ec);
            result.test_sz_eq("server application send size", n, server_payload.size());
         });
      }
   };
   server.async_handshake(Botan::TLS::Connection_Side::Server, [&](error_code ec) {
      if(++server_handshakes != 1) {
         return;
      }
      result.test_is_true("server handshake succeeds", !ec);
      failed |= static_cast<bool>(ec);
      if(ec) {
         cancel_pair();
         return;
      }
      if(control->drop_first_final_flight == ControlledDatagramLayer::Direction::ServerToClient) {
         result.test_is_true("server completes before client receives its final flight",
                             !client.native_handle()->is_active());
      }
      // Keep reading on the early-completing side to process duplicate final flights.
      server.async_receive(net::buffer(server_buffer), [&](error_code receive_ec, size_t n) {
         ++server_receives;
         result.test_is_true("server application receive succeeds", !receive_ec);
         result.test_sz_eq("server application receive size", n, client_payload.size());
         result.test_bin_eq("server receives client payload", server_buffer, client_payload);
      });
      start_sends();
   });
   client.async_handshake(Botan::TLS::Connection_Side::Client, [&](error_code ec) {
      if(++client_handshakes != 1) {
         return;
      }
      result.test_is_true("client handshake succeeds", !ec);
      failed |= static_cast<bool>(ec);
      if(ec) {
         cancel_pair();
         return;
      }
      if(control->drop_first_final_flight == ControlledDatagramLayer::Direction::ClientToServer) {
         result.test_is_true("resumed client activates before server receives its final flight",
                             !server.native_handle()->is_active());
      }
      client.async_receive(net::buffer(client_buffer), [&](error_code receive_ec, size_t n) {
         ++client_receives;
         result.test_is_true("client application receive succeeds", !receive_ec);
         result.test_sz_eq("client application receive size", n, server_payload.size());
         result.test_bin_eq("client receives server payload", client_buffer, server_payload);
      });
      start_sends();
   });
   run_until_or_fail(
      io,
      result,
      [&] { return failed || (client_sends > 0 && server_sends > 0 && client_receives > 0 && server_receives > 0); },
      cancel_pair,
      "final-flight recovery and application exchange timed out");
   result.test_is_true("client reports expected resumption", client_callbacks->resumed() == expect_resumption);
   result.test_is_true("server reports expected resumption", server_callbacks->resumed() == expect_resumption);
   result.test_is_true("client is active after exchange", client.native_handle()->is_active());
   result.test_is_true("server is active after exchange", server.native_handle()->is_active());
   if(control->drop_first_final_flight) {
      result.test_sz_eq("initial final-flight CCS was dropped", control->dropped_ccs, 1);
      result.test_sz_eq("initial encrypted Finished was dropped", control->dropped_finished, 1);
   }
   // Observe beyond three maximum retransmission intervals without cancellation,
   // so lingering timer chains cannot hide behind test cleanup.
   const auto handshake_records = control->handshake_records_sent;
   net::steady_timer quiet(io, std::chrono::milliseconds(150));
   quiet.async_wait([](error_code) {});
   io.run_for(std::chrono::milliseconds(200));
   io.restart();
   result.test_sz_eq("no unsolicited handshake traffic after peer application exchange",
                     control->handshake_records_sent,
                     handshake_records);
   result.test_sz_eq("client handshake completes exactly once", client_handshakes, 1);
   result.test_sz_eq("server handshake completes exactly once", server_handshakes, 1);
   result.test_sz_eq("client send completes exactly once", client_sends, 1);
   result.test_sz_eq("server send completes exactly once", server_sends, 1);
   result.test_sz_eq("client receive completes exactly once", client_receives, 1);
   result.test_sz_eq("server receive completes exactly once", server_receives, 1);
   result.test_sz_eq("client establishes one session", client_callbacks->established_calls(), 1);
   result.test_sz_eq("server establishes one session", server_callbacks->established_calls(), 1);
   cancel_pair();
   io.run_for(std::chrono::milliseconds(1));
}

Test::Result test_udp_handshake_cancellation() {
   Test::Result result("DTLS ASIO datagram UDP handshake slot cancellation");
   net::io_context io;
   auto context =
      get_real_context(std::make_shared<TestCredentials>(true, ""), std::make_shared<Botan::TLS::Datagram_Policy>());
   udp::socket socket(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   const udp::socket silent_peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   socket.connect(silent_peer.local_endpoint());
   Botan::TLS::Datagram<udp::socket> datagram(context, std::move(socket));
   net::cancellation_signal signal;
   net::steady_timer cancellation(io);
   cancellation.expires_after(std::chrono::milliseconds(5));
   cancellation.async_wait([&](error_code ec) {
      if(!ec) {
         signal.emit(net::cancellation_type::terminal);
      }
   });
   size_t completions = 0;
   error_code handshake_ec;
   datagram.async_handshake(Botan::TLS::Connection_Side::Client,
                            net::bind_cancellation_slot(signal.slot(), [&](error_code ec) {
                               ++completions;
                               handshake_ec = ec;
                            }));
   run_until_or_fail(
      io,
      result,
      [&] { return completions > 0; },
      [&] { datagram.cancel(); },
      "slot cancellation left UDP handshake pending");
   result.test_is_true("UDP handshake observes slot cancellation", handshake_ec == net::error::operation_aborted);
   result.test_sz_eq("UDP handshake completes once", completions, 1);
   return result;
}

Test::Result test_udp_receive_cancellation() {
   Test::Result result("DTLS ASIO datagram UDP receive slot cancellation");
   net::io_context io;
   auto datagrams = make_real_datagram_pair(make_udp_pair(io));
   auto& client = datagrams.first;
   auto& server = datagrams.second;
   auto [client_ec, server_ec] = run_handshake_pair(io, client, server, result, "UDP cancellation handshake timed out");
   result.test_is_true("client handshake succeeds", !client_ec);
   result.test_is_true("server handshake succeeds", !server_ec);
   if(!client_ec && !server_ec) {
      net::cancellation_signal signal;
      std::array<uint8_t, 32> client_buffer{};
      std::array<uint8_t, 32> server_buffer{};
      const auto payload = vec("independent send");
      Completion receive;
      Completion send;
      Completion peer;
      client.async_receive(net::buffer(client_buffer), net::bind_cancellation_slot(signal.slot(), receive.handler()));
      io.poll();  // Drain any ready protocol records, leaving an idle native receive.
      result.test_sz_eq("UDP receive is pending before cancellation", receive.calls(), 0);
      client.async_send(net::buffer(payload), send.handler());
      server.async_receive(net::buffer(server_buffer), peer.handler());
      signal.emit(net::cancellation_type::terminal);
      result.test_sz_eq("UDP cancellation completion is not inline", receive.calls(), 0);
      run_until_or_fail(
         io,
         result,
         [&] { return receive.calls() > 0 && send.calls() > 0 && peer.calls() > 0; },
         [&] { close_pair(client, server); },
         "UDP slot cancellation left application I/O pending");
      result.test_sz_eq("cancelled UDP receive returns no plaintext", receive.bytes(), 0);
      result.test_sz_eq("overlapping UDP send retains size", send.bytes(), payload.size());
      result.test_bin_eq("peer receives overlapping send",
                         std::vector<uint8_t>(server_buffer.begin(), server_buffer.begin() + peer.bytes()),
                         payload);
      result.test_is_true("native UDP receive observes slot cancellation",
                          receive.error() == net::error::operation_aborted);
      result.test_is_true("overlapping UDP send succeeds", !send.error());
      result.test_is_true("peer receive succeeds", !peer.error());
      result.test_sz_eq("UDP receive completes exactly once", receive.calls(), 1);
      result.test_sz_eq("UDP send completes exactly once", send.calls(), 1);
      result.test_sz_eq("peer receive completes exactly once", peer.calls(), 1);
      result.test_is_true("slot cancellation leaves UDP socket open", client.lowest_layer().is_open());
      result.test_is_true("UDP cancellation slot is detached", !signal.slot().has_handler());
      client.cancel();
      server.cancel();
      io.run();
   }
   return result;
}

Test::Result test_peer_identity() {
   Test::Result result("DTLS ASIO datagram peer network identity");
   net::io_context io;
   udp::socket socket(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   const udp::socket peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   socket.connect(peer.local_endpoint());
   auto callbacks = std::make_shared<Botan::TLS::DatagramCallbacks>();
   const Botan::TLS::Datagram<udp::socket> datagram(get_context(), callbacks, {}, std::move(socket));
   const auto expected =
      peer.local_endpoint().address().to_string() + ":" + std::to_string(peer.local_endpoint().port());
   result.test_is_true("identity is the actual connected peer", callbacks->tls_peer_network_identity() == expected);
   return result;
}

Test::Result test_sync_timer_error() {
   Test::Result result("DTLS ASIO datagram synchronous handshake timer error");
   net::io_context io;
   auto context =
      get_real_context(std::make_shared<TestCredentials>(true, ""), std::make_shared<NoRetransmissionsPolicy>());
   udp::socket socket(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   const udp::socket silent_peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   socket.connect(silent_peer.local_endpoint());
   Botan::TLS::Datagram<udp::socket> datagram(context, std::move(socket));
   error_code ec;
   datagram.handshake(Botan::TLS::Connection_Side::Client, ec);
   result.test_is_true("timer failure reaches synchronous caller", ec == net::error::timed_out);
   result.test_is_true("socket blocking mode is restored", !datagram.lowest_layer().non_blocking());
   return result;
}

Test::Result test_async_timer_error() {
   Test::Result result("DTLS ASIO datagram timer error completes pending handshake");
   net::io_context io;
   auto context =
      get_real_context(std::make_shared<TestCredentials>(true, ""), std::make_shared<NoRetransmissionsPolicy>());
   udp::socket socket(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   const udp::socket silent_peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
   socket.connect(silent_peer.local_endpoint());
   Botan::TLS::Datagram<udp::socket> datagram(context, std::move(socket));
   Completion handshake;
   datagram.async_handshake(Botan::TLS::Connection_Side::Client, handshake.handler());
   run_until_or_fail(
      io,
      result,
      [&] { return handshake.calls() > 0; },
      [&] { datagram.lowest_layer().close(); },
      "timer failure left handshake pending");
   result.test_sz_eq("handshake completes exactly once", handshake.calls(), 1);
   result.test_is_true("original timer error is reported", handshake.error() == net::error::timed_out);
   return result;
}

Test::Result test_client_initial_flight_drop() {
   Test::Result result("DTLS ASIO datagram handshake retransmits after drop");
   net::io_context io;

   auto control = std::make_shared<ControlledDatagramLayer::Control>();
   control->drop_first_client_to_server = true;
   auto [client, server] = make_real_datagram_pair(ControlledDatagramLayer::make_pair(io, control));
   auto [client_ec, server_ec] =
      run_handshake_pair(io, client, server, result, "handshake with dropped initial datagram timed out");

   result.test_is_true("first client datagram was dropped", control->dropped == 1);
   result.test_is_true("client retransmitted handshake datagram", control->client_to_server_sent > 1);
   result.test_is_true("client handshake succeeds", !client_ec);
   result.test_is_true("server handshake succeeds", !server_ec);
   return result;
}

Test::Result test_hello_verify_request_drop() {
   Test::Result result("DTLS ASIO datagram handshake retransmits lost HelloVerifyRequest");
   net::io_context io;

   auto control = std::make_shared<ControlledDatagramLayer::Control>();
   control->drop_first_server_to_client = true;
   auto [client, server] = make_real_datagram_pair(ControlledDatagramLayer::make_pair(io, control));
   auto [client_ec, server_ec] =
      run_handshake_pair(io, client, server, result, "handshake with dropped HelloVerifyRequest timed out");

   result.test_is_true("first server datagram was dropped", control->dropped == 1);
   result.test_is_true("server retransmitted HelloVerifyRequest", control->server_to_client_sent > 1);
   result.test_is_true("client handshake succeeds", !client_ec);
   result.test_is_true("server handshake succeeds", !server_ec);
   return result;
}

Test::Result test_reordered_server_flight() {
   Test::Result result("DTLS ASIO datagram handshake tolerates out of order flight");
   net::io_context io;

   auto control = std::make_shared<ControlledDatagramLayer::Control>();
   control->reorder_first_server_flight = true;
   auto [client, server] = make_real_datagram_pair(ControlledDatagramLayer::make_pair(io, control));
   auto [client_ec, server_ec] =
      run_handshake_pair(io, client, server, result, "handshake with reordered server flight timed out");

   result.test_is_true("server flight was reordered", control->reordered == 1);
   result.test_is_true("client handshake succeeds", !client_ec);
   result.test_is_true("server handshake succeeds", !server_ec);
   return result;
}

Test::Result test_server_final_flight() {
   Test::Result result("DTLS ASIO datagram full handshake recovers lost server final flight");
   auto client_context = get_real_context(std::make_shared<Basic_Credentials_Manager>(true, ""));
   client_context->set_verify_callback(accept_all);
   auto server_context = get_real_context(std::make_shared<TestCredentials>(server_cert(), server_key()));
   auto control = std::make_shared<ControlledDatagramLayer::Control>();
   control->drop_first_final_flight = ControlledDatagramLayer::Direction::ServerToClient;
   check_final_flight_exchange(result, client_context, server_context, control, false);
   return result;
}

Test::Result test_resumed_client_final_flight() {
   Test::Result result(
      "DTLS ASIO datagram resumed client final flight "
      "retransmits after activation");
   auto client_context = get_resumable_context(std::make_shared<Basic_Credentials_Manager>(true, ""));
   client_context->set_verify_callback(accept_all);
   auto server_context = get_resumable_context(std::make_shared<TestCredentials>(server_cert(), server_key()));
   check_final_flight_exchange(
      result, client_context, server_context, std::make_shared<ControlledDatagramLayer::Control>(), false);
   auto control = std::make_shared<ControlledDatagramLayer::Control>();
   control->drop_first_final_flight = ControlledDatagramLayer::Direction::ClientToServer;
   check_final_flight_exchange(result, client_context, server_context, control, true);
   return result;
}

Test::Result test_background_retransmission_cancel() {
   Test::Result result(
      "DTLS ASIO datagram cancellation during background "
      "handshake retransmission");
   net::io_context io;
   auto control = std::make_shared<ControlledDatagramLayer::Control>();
   control->drop_first_client_to_server = true;
   control->hold_next_send = ControlledDatagramLayer::Direction::ClientToServer;
   control->hold_after_sends = 1;
   auto datagrams = make_real_datagram_pair(ControlledDatagramLayer::make_pair(io, control));
   auto& client = datagrams.first;
   auto& server = datagrams.second;
   size_t client_handshakes = 0;
   size_t server_handshakes = 0;
   error_code client_error;
   error_code server_error;
   control->on_send_held = [&] {
      // The initial ClientHello was lost. Hold the timer-driven retry
      // in flight, then cancel before its transport completion.
      server.cancel();
      client.cancel();
   };
   server.async_handshake(Botan::TLS::Connection_Side::Server, [&](error_code ec) {
      ++server_handshakes;
      server_error = ec;
   });
   client.async_handshake(Botan::TLS::Connection_Side::Client, [&](error_code ec) {
      ++client_handshakes;
      client_error = ec;
   });
   run_until_or_fail(
      io,
      result,
      [&] { return client_handshakes > 0 && server_handshakes > 0 && control->held_send_completions > 0; },
      [&] {
         client.cancel();
         server.cancel();
         client.lowest_layer().close();
         server.lowest_layer().close();
      },
      "cancellation during timer-driven handshake send timed out");
   result.test_sz_eq("client handshake completes exactly once", client_handshakes, 1);
   result.test_sz_eq("server handshake completes exactly once", server_handshakes, 1);
   result.test_sz_eq("one background send was held", control->held_sends, 1);
   result.test_sz_eq("held send was cancelled exactly once", control->aborted_sends, 1);
   result.test_sz_eq("held send completes exactly once", control->held_send_completions, 1);
   result.test_sz_eq("initial ClientHello was dropped", control->dropped, 1);
   result.test_is_true("client timer retransmitted ClientHello", control->client_to_server_sent >= 2);
   result.test_is_true("client handshake reports operation_aborted", client_error == net::error::operation_aborted);
   result.test_is_true("server handshake reports operation_aborted", server_error == net::error::operation_aborted);
   const auto handshake_records = control->handshake_records_sent;
   net::steady_timer quiet(io, std::chrono::milliseconds(150));
   quiet.async_wait([](error_code) {});
   io.run_for(std::chrono::milliseconds(200));
   io.restart();
   result.test_sz_eq("cancelled retransmission stays stopped", control->handshake_records_sent, handshake_records);
   result.test_sz_eq("no late duplicate client completion", client_handshakes, 1);
   result.test_sz_eq("no late duplicate server completion", server_handshakes, 1);
   control->on_send_held = {};
   return result;
}

Test::Result test_pending_receive_close() {
   Test::Result result("DTLS ASIO datagram pending receive completes on socket close");
   net::io_context io;
   auto [socket, peer] = make_udp_pair(io);
   Botan::TLS::Datagram datagram(get_context(), std::move(socket));
   std::array<uint8_t, 16> buffer{};
   Completion receive;
   datagram.async_receive(net::buffer(buffer), receive.handler());
   net::post(io, [&] { datagram.lowest_layer().close(); });
   run_until_or_fail(
      io,
      result,
      [&] { return receive.calls() > 0; },
      [&] { datagram.lowest_layer().close(); },
      "pending receive close timed out");
   result.test_sz_eq("pending receive completes exactly once", receive.calls(), 1);
   result.test_is_true("pending receive reports an error", static_cast<bool>(receive.error()));
   return result;
}

Test::Result test_pending_handshake_close() {
   Test::Result result("DTLS ASIO datagram pending handshake completes on socket close");
   net::io_context io;
   auto datagrams = make_real_datagram_pair(make_udp_pair(io));
   auto& client = datagrams.first;
   auto& server = datagrams.second;
   Completion client_handshake;
   Completion server_handshake;
   server.async_handshake(Botan::TLS::Connection_Side::Server, server_handshake.handler());
   client.async_handshake(Botan::TLS::Connection_Side::Client, client_handshake.handler());
   net::post(io, [&] { close_pair(client, server); });
   run_until_or_fail(
      io,
      result,
      [&] { return client_handshake.calls() > 0 && server_handshake.calls() > 0; },
      [&] { close_pair(client, server); },
      "pending handshake close timed out");
   result.test_sz_eq("client handshake completes exactly once", client_handshake.calls(), 1);
   result.test_sz_eq("server handshake completes exactly once", server_handshake.calls(), 1);
   result.test_is_true("client handshake reports an error", static_cast<bool>(client_handshake.error()));
   result.test_is_true("server handshake reports an error", static_cast<bool>(server_handshake.error()));
   return result;
}

Test::Result test_udp_echo() {
   Test::Result result("DTLS ASIO datagram UDP handshake echo");
   net::io_context io;
   auto datagrams = make_real_datagram_pair(make_udp_pair(io));
   auto& client = datagrams.first;
   auto& server = datagrams.second;
   auto [client_ec, server_ec] = run_handshake_pair(io, client, server, result, "handshake timed out");
   result.test_is_true("client handshake succeeds", !client_ec);
   result.test_is_true("server handshake succeeds", !server_ec);
   const std::array<uint8_t, 4> ping = {'p', 'i', 'n', 'g'};
   std::array<uint8_t, 4> received{};
   Completion send;
   Completion receive;
   server.async_receive(net::buffer(received), receive.handler());
   client.async_send(net::buffer(ping), send.handler());
   run_until_or_fail(
      io,
      result,
      [&] { return send.calls() > 0 && receive.calls() > 0; },
      [&] { close_pair(client, server); },
      "echo timed out");
   result.test_is_true("send succeeds", !send.error());
   result.test_is_true("receive succeeds", !receive.error());
   result.test_sz_eq("received application datagram size", receive.bytes(), ping.size());
   result.test_bin_eq("received application datagram",
                      std::vector<uint8_t>(received.begin(), received.end()),
                      std::vector<uint8_t>(ping.begin(), ping.end()));
   return result;
}

}  // namespace

std::vector<Test::Result> run_asio_datagram_integration_tests() {
   return {
      test_udp_handshake_cancellation(),
      test_udp_receive_cancellation(),
      test_peer_identity(),
      test_sync_timer_error(),
      test_async_timer_error(),
      test_client_initial_flight_drop(),
      test_hello_verify_request_drop(),
      test_reordered_server_flight(),
      test_server_final_flight(),
      test_resumed_client_final_flight(),
      test_background_retransmission_cancel(),
      test_pending_receive_close(),
      test_pending_handshake_close(),
      test_udp_echo(),
   };
}

}  // namespace Botan_Tests::Asio_Datagram_Test

   #endif
#endif  // BOTAN_HAS_TLS && BOTAN_HAS_TLS_ASIO_STREAM
