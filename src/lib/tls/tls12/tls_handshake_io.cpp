/*
* TLS Handshake IO
* (C) 2012,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_io.h>

#include <botan/exceptn.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_handshake_msg.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>

namespace Botan::TLS {

namespace {

// How many ClientHellos a server will take before it commits to a handshake by
// sending a flight. The exchange RFC 6347 4.2.1 describes needs two; the rest
// absorb a cookie secret rotation. Each one advances the expected sequence, so
// this is also what keeps that counter from being driven around by
// unauthenticated input.
constexpr uint16_t MAX_PRE_COMMIT_CLIENT_HELLOS = 8;

inline size_t load_be24(const uint8_t q[3]) {
   return make_uint32(0, q[0], q[1], q[2]);
}

// Reject handshake type values that are internal sentinels, not wire values
void verify_is_expected_wire_handshake_type(Handshake_Type type) {
   switch(type) {
      case Handshake_Type::HelloRetryRequest:
      case Handshake_Type::HandshakeCCS:
      case Handshake_Type::None:
         throw TLS_Exception(Alert::UnexpectedMessage, "Invalid handshake message type");
      default:
         break;
   }
}

void store_be24(uint8_t out[3], size_t val) {
   out[0] = get_byte<1>(static_cast<uint32_t>(val));
   out[1] = get_byte<2>(static_cast<uint32_t>(val));
   out[2] = get_byte<3>(static_cast<uint32_t>(val));
}

}  // namespace

Protocol_Version Stream_Handshake_IO::initial_record_version() const {
   return Protocol_Version::TLS_V12;
}

void Stream_Handshake_IO::add_record(const uint8_t record[],
                                     size_t record_len,
                                     Record_Type record_type,
                                     uint64_t /*sequence_number*/) {
   if(record_type == Record_Type::Handshake) {
      m_queue.insert(m_queue.end(), record, record + record_len);
   } else if(record_type == Record_Type::ChangeCipherSpec) {
      if(record_len != 1 || record[0] != 1) {
         throw Decoding_Error("Invalid ChangeCipherSpec");
      }

      // Pretend it's a regular handshake message of zero length
      const uint8_t ccs_hs[] = {static_cast<uint8_t>(Handshake_Type::HandshakeCCS), 0, 0, 0};
      m_queue.insert(m_queue.end(), ccs_hs, ccs_hs + sizeof(ccs_hs));
   } else {
      throw Decoding_Error("Unknown message type " + std::to_string(static_cast<size_t>(record_type)) +
                           " in handshake processing");
   }
}

std::pair<Handshake_Type, std::vector<uint8_t>> Stream_Handshake_IO::get_next_record(bool expecting_ccs,
                                                                                     size_t max_message_size) {
   if(m_queue.size() >= 4) {
      const Handshake_Type type = static_cast<Handshake_Type>(m_queue[0]);

      const size_t rec_length = make_uint32(0, m_queue[1], m_queue[2], m_queue[3]);

      // If we are expecting a CCS but the next queued message is not a CCS,
      // the peer has skipped the CCS message. This can happen when the peer
      // sends an encrypted Finished without the preceding CCS, in which case
      // the encrypted bytes are misinterpreted as a handshake message.
      if(expecting_ccs) {
         const bool is_ccs = (type == Handshake_Type::HandshakeCCS && rec_length == 0);
         if(!is_ccs) {
            throw TLS_Exception(Alert::UnexpectedMessage, "Expected ChangeCipherSpec but got a handshake message");
         }
      } else {
         verify_is_expected_wire_handshake_type(type);

         if(max_message_size > 0 && rec_length > max_message_size) {
            throw TLS_Exception(
               Alert::HandshakeFailure,
               Botan::fmt("Handshake message is {} bytes, policy maximum is {}", rec_length, max_message_size));
         }
      }

      const size_t length = 4 + rec_length;

      if(m_queue.size() >= length) {
         const std::vector<uint8_t> contents(m_queue.begin() + 4, m_queue.begin() + length);

         m_queue.erase(m_queue.begin(), m_queue.begin() + length);

         return std::make_pair(type, contents);
      }
   }

   return std::make_pair(Handshake_Type::None, std::vector<uint8_t>());
}

std::vector<uint8_t> Stream_Handshake_IO::format(const std::vector<uint8_t>& msg, Handshake_Type type) const {
   std::vector<uint8_t> send_buf(4 + msg.size());

   const size_t buf_size = msg.size();

   send_buf[0] = static_cast<uint8_t>(type);

   store_be24(&send_buf[1], buf_size);

   if(!msg.empty()) {
      copy_mem(&send_buf[4], msg.data(), msg.size());
   }

   return send_buf;
}

std::vector<uint8_t> Stream_Handshake_IO::send_under_epoch(const Handshake_Message& /*msg*/, uint16_t /*epoch*/) {
   throw Invalid_State("Not possible to send under arbitrary epoch with stream based TLS");
}

std::vector<uint8_t> Stream_Handshake_IO::send(const Handshake_Message& msg) {
   const std::vector<uint8_t> msg_bits = msg.serialize();

   if(msg.type() == Handshake_Type::HandshakeCCS) {
      m_send_hs(Record_Type::ChangeCipherSpec, msg_bits);
      return std::vector<uint8_t>();  // not included in handshake hashes
   }

   auto buf = format(msg_bits, msg.wire_type());
   m_send_hs(Record_Type::Handshake, buf);
   return buf;
}

namespace {

size_t max_pending_reassembly(size_t policy_hs_max) {
   constexpr size_t overall_cap = 1024 * 1024;  // arbitrary

   if(policy_hs_max == 0) {
      return overall_cap;
   } else {
      return std::min<size_t>(policy_hs_max * 4, overall_cap);
   }
}

}  // namespace

Datagram_Handshake_IO::Datagram_Handshake_IO(writer_fn writer,
                                             steady_clock_fn steady_clock_ms,
                                             class Connection_Sequence_Numbers& seq,
                                             uint16_t mtu,
                                             uint64_t initial_timeout_ms,
                                             uint64_t max_timeout_ms,
                                             std::optional<size_t> max_retransmissions,
                                             size_t max_handshake_msg_size,
                                             bool is_server) :
      m_seqs(seq),
      m_flights(1),
      m_flight_ccs(1),
      m_initial_timeout(initial_timeout_ms),
      m_max_timeout(max_timeout_ms),
      m_max_retransmissions(max_retransmissions),
      m_send_hs(std::move(writer)),
      m_steady_clock_ms(std::move(steady_clock_ms)),
      m_mtu(mtu),
      m_max_handshake_msg_size(max_handshake_msg_size),
      m_max_pending_reassembly(max_pending_reassembly(m_max_handshake_msg_size)),
      m_is_server(is_server) {}

Protocol_Version Datagram_Handshake_IO::initial_record_version() const {
   return Protocol_Version::DTLS_V12;
}

void Datagram_Handshake_IO::retransmit_last_flight() {
   // m_flights keeps an empty trailing slot while waiting for the peer, so the
   // last completed flight is normally the one before it.
   const size_t flight_idx = (m_flights.size() == 1) ? 0 : (m_flights.size() - 2);
   retransmit_flight(flight_idx);
   m_last_write = m_steady_clock_ms();
}

void Datagram_Handshake_IO::retransmit_flight(size_t flight_idx) {
   const auto& flight = m_flights.at(flight_idx);
   const auto& ccs_records = m_flight_ccs.at(flight_idx);
   const std::vector<uint8_t> ccs = {1};

   BOTAN_ASSERT(!flight.empty(), "Nonempty flight to retransmit");

   size_t ccs_idx = 0;
   for(size_t msg_idx = 0; msg_idx != flight.size(); ++msg_idx) {
      while(ccs_idx != ccs_records.size() && ccs_records[ccs_idx].first == msg_idx) {
         m_send_hs(ccs_records[ccs_idx].second, Record_Type::ChangeCipherSpec, ccs);
         ++ccs_idx;
      }

      const auto msg_seq = flight[msg_idx];
      const auto& msg = m_flight_data.at(msg_seq);
      send_message(msg_seq, msg.epoch, msg.msg_type, msg.msg_bits);
   }

   while(ccs_idx != ccs_records.size() && ccs_records[ccs_idx].first == flight.size()) {
      m_send_hs(ccs_records[ccs_idx].second, Record_Type::ChangeCipherSpec, ccs);
      ++ccs_idx;
   }
}

bool Datagram_Handshake_IO::have_more_data() const {
   if(m_retransmitted_client_hello.has_value() && m_retransmitted_client_hello->second.complete()) {
      return true;
   }

   // Future or incomplete fragments remain buffered, but only a complete
   // next-in-sequence message is trailing handshake data. A buffered duplicate
   // ClientHello is not: it carries nothing the peer has not already sent, and
   // get_next_record only reaches for it when there is no in-sequence message.
   const auto next = m_messages.find(m_in_message_seq);
   return next != m_messages.end() && next->second.complete();
}

void Datagram_Handshake_IO::finalize_handshake(bool retransmit_terminal_flight) {
   // Keep an empty trailing flight to mean "we are waiting for the peer".
   // Retransmission then replays the previous, completed flight instead of
   // appending to it.
   if(!m_flights.rbegin()->empty()) {
      m_flights.emplace_back();
      m_flight_ccs.emplace_back();
   }

   // RFC 6347 4.2.4 transitions directly to FINISHED after sending the
   // terminal flight. Keep the flight for reactive replay when the peer
   // retransmits, but do not arm a proactive retransmission timer.
   m_finished = true;
   m_retransmit_terminal_flight = retransmit_terminal_flight;
}

bool Datagram_Handshake_IO::timeout_check() {
   const auto timeout = next_retransmission_timeout();
   if(!timeout || timeout->count() > 0) {
      return false;
   }

   // The retransmit timer has expired. Count this attempt and, once the
   // configured cap is reached, abandon the handshake rather than retransmit
   // forever. RFC 6347 4.2.4.1 gives the backoff schedule but states no
   // condition for giving up, so the cap is local policy, not a requirement.
   // No alert is sent - the peer is by definition unresponsive.
   m_retransmit_count += 1;
   if(m_max_retransmissions.has_value() && m_retransmit_count > m_max_retransmissions.value()) {
      throw TLS_Exception(Alert::None, "DTLS handshake timed out: maximum retransmissions exceeded");
   }

   // retransmit_last_flight re-anchors m_last_write. Without that, once
   // m_next_timeout saturates at m_max_timeout the elapsed time keeps growing
   // and every subsequent poll fires another retransmission.
   retransmit_last_flight();

   m_next_timeout = std::min(2 * m_next_timeout, m_max_timeout);
   return true;
}

std::optional<std::chrono::milliseconds> Datagram_Handshake_IO::next_retransmission_timeout() const {
   if(m_finished) {
      return std::nullopt;
   }

   // Without an outgoing flight, or while constructing one, there is nothing
   // complete that timeout_check() could retransmit.
   if(!m_last_write.has_value() || (m_flights.size() > 1 && !m_flights.rbegin()->empty())) {
      return std::nullopt;
   }

   const uint64_t ms_since_write = m_steady_clock_ms() - m_last_write.value();
   if(ms_since_write >= m_next_timeout) {
      return std::chrono::milliseconds(0);
   }

   // BoringSSL reports a sub-15ms remainder as zero (ssl/d1_lib.cc
   // DTLSTimer::MicrosecondsRemaining) to absorb divergence with caller
   // scheduling; BoGo's DTLS-Retransmit-Fudge test requires it. The cap keeps
   // the fudge from swallowing the very short timers some tests configure.
   const uint64_t fudge_ms = std::min<uint64_t>(15, m_initial_timeout / 2);
   const uint64_t remaining_ms = m_next_timeout - ms_since_write;

   return std::chrono::milliseconds(remaining_ms <= fudge_ms ? 0 : remaining_ms);
}

void Datagram_Handshake_IO::add_record(const uint8_t record[],
                                       size_t record_len,
                                       Record_Type record_type,
                                       uint64_t record_sequence) {
   add_record(record, record_len, record_type, record_sequence, false);
}

void Datagram_Handshake_IO::add_retransmitted_record(const uint8_t record[],
                                                     size_t record_len,
                                                     Record_Type record_type,
                                                     uint64_t record_sequence) {
   add_record(record, record_len, record_type, record_sequence, true);
}

bool Datagram_Handshake_IO::reassemble_retransmitted_fragment(const uint8_t fragment[],
                                                              size_t fragment_length,
                                                              size_t fragment_offset,
                                                              uint16_t epoch,
                                                              Handshake_Type msg_type,
                                                              size_t msg_length,
                                                              uint16_t message_seq) {
   auto [i, inserted] = m_retransmitted_messages.try_emplace(msg_type, message_seq, Handshake_Reassembly{});

   if(!inserted && i->second.first != message_seq) {
      release_reassembly_bytes(i->second.second);
      i->second = std::make_pair(message_seq, Handshake_Reassembly());
   }

   auto& reassembly = i->second.second;

   // These buffers hold unauthenticated input, so they are charged against the
   // same budget as the main reassembly path rather than growing on their own.
   if(!charged_add_fragment(reassembly,
                            m_max_pending_reassembly,
                            fragment,
                            fragment_length,
                            fragment_offset,
                            epoch,
                            msg_type,
                            msg_length)) {
      return false;
   }

   if(!reassembly.complete()) {
      return false;
   }

   release_reassembly_bytes(reassembly);
   m_retransmitted_messages.erase(i);
   return true;
}

bool Datagram_Handshake_IO::charged_add_fragment(Handshake_Reassembly& reassembly,
                                                 size_t ceiling,
                                                 const uint8_t fragment[],
                                                 size_t fragment_length,
                                                 size_t fragment_offset,
                                                 uint16_t epoch,
                                                 Handshake_Type msg_type,
                                                 size_t msg_length) {
   // Preflight the merge so overlap with already-buffered segments is not
   // charged twice: near the ceiling, a whole-message retransmission landing
   // on top of a partially received copy must stay admissible.
   const size_t charged_before = reassembly.charged_bytes();
   const size_t charged_after = reassembly.charged_bytes_after_add(fragment_length, fragment_offset);
   BOTAN_ASSERT_NOMSG(m_pending_reassembly_bytes >= charged_before);
   if(m_pending_reassembly_bytes - charged_before + charged_after > ceiling) {
      return false;
   }

   try {
      reassembly.add_fragment(fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length);
   } catch(...) {
      recharge_reassembly_bytes(charged_before, reassembly);
      throw;
   }
   recharge_reassembly_bytes(charged_before, reassembly);
   return true;
}

void Datagram_Handshake_IO::release_reassembly_bytes(const Handshake_Reassembly& reassembly) {
   BOTAN_ASSERT_NOMSG(m_pending_reassembly_bytes >= reassembly.charged_bytes());
   m_pending_reassembly_bytes -= reassembly.charged_bytes();
}

void Datagram_Handshake_IO::recharge_reassembly_bytes(size_t charged_before, const Handshake_Reassembly& reassembly) {
   const size_t charged_after = reassembly.charged_bytes();

   if(charged_after >= charged_before) {
      m_pending_reassembly_bytes += charged_after - charged_before;
   } else {
      const size_t refund = charged_before - charged_after;
      BOTAN_ASSERT_NOMSG(m_pending_reassembly_bytes >= refund);
      m_pending_reassembly_bytes -= refund;
   }
}

bool Datagram_Handshake_IO::process_previous_handshake_fragment(const uint8_t fragment[],
                                                                size_t fragment_length,
                                                                size_t fragment_offset,
                                                                uint16_t epoch,
                                                                Handshake_Type msg_type,
                                                                size_t msg_length,
                                                                uint16_t message_seq,
                                                                bool retransmitted_flight) {
   // Empty fragments of non-empty messages add no information and must not
   // trigger a flight retransmission. A zero-length message such as
   // ServerHelloDone is not an empty fragment in this sense.
   if(fragment_length == 0 && msg_length != 0) {
      return false;
   }

   // HelloVerifyRequest has no retransmission timer or cached flight. Feed a
   // retransmitted initial ClientHello back to the server handshake logic so
   // it can recreate the stateless cookie response instead.
   if(msg_type == Handshake_Type::ClientHello) {
      // A declared length this short cannot be a real ClientHello, so it cannot
      // be a retransmission of one. Without this a bare 12-byte handshake
      // header claiming msg_length 0 counts as a fully reassembled message and
      // buys a whole flight replay.
      if(msg_length < Datagram_Handshake_IO::MIN_CLIENT_HELLO_SIZE) {
         return false;
      }

      if(!retransmitted_flight && m_awaiting_cookie_client_hello) {
         if(!m_retransmitted_client_hello.has_value() || m_retransmitted_client_hello->first != message_seq) {
            if(m_retransmitted_client_hello.has_value()) {
               release_reassembly_bytes(m_retransmitted_client_hello->second);
            }
            m_retransmitted_client_hello = std::make_pair(message_seq, Handshake_Reassembly());
         }

         charged_add_fragment(m_retransmitted_client_hello->second,
                              m_max_pending_reassembly,
                              fragment,
                              fragment_length,
                              fragment_offset,
                              epoch,
                              msg_type,
                              msg_length);
         return false;
      }

      return reassemble_retransmitted_fragment(
         fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length, message_seq);
   }

   // Other previous-flight messages request an immediate response only after
   // the handshake IO was retained by an active association. While pending,
   // the normal retransmission timer handles recovery.
   if(!retransmitted_flight) {
      return false;
   }

   if(msg_type == Handshake_Type::ServerHello) {
      m_retransmitted_server_hello_complete = reassemble_retransmitted_fragment(
         fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length, message_seq);

      if(m_retransmitted_server_hello_complete && m_retransmitted_server_hello_done_complete) {
         m_retransmitted_server_hello_complete = false;
         m_retransmitted_server_hello_done_complete = false;
         return true;
      }
   } else if(msg_type == Handshake_Type::ServerHelloDone && msg_length == 0) {
      if(reassemble_retransmitted_fragment(
            fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length, message_seq)) {
         m_retransmitted_server_hello_done_complete = true;
         if(m_retransmitted_server_hello_complete) {
            m_retransmitted_server_hello_complete = false;
            m_retransmitted_server_hello_done_complete = false;
            return true;
         }
      }
   } else if(msg_type == Handshake_Type::Finished &&
             reassemble_retransmitted_fragment(
                fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length, message_seq)) {
      // A final-flight retransmission includes CCS, but UDP may deliver its
      // records in either order. Wait until both have been observed.
      if(m_retransmitted_ccs_epoch == epoch) {
         m_retransmitted_ccs_epoch.reset();
         return true;
      }

      m_retransmitted_finished_epoch = epoch;
   }

   return false;
}

void Datagram_Handshake_IO::add_record(const uint8_t record[],
                                       size_t record_len,
                                       Record_Type record_type,
                                       uint64_t record_sequence,
                                       bool retransmitted_flight) {
   const uint16_t epoch = static_cast<uint16_t>(record_sequence >> 48);

   if(record_type == Record_Type::ChangeCipherSpec) {
      if(record_len != 1 || record[0] != 1) {
         throw Decoding_Error("Invalid ChangeCipherSpec");
      }

      // TODO: check this is otherwise empty
      m_ccs_epochs.insert(epoch);
      if(retransmitted_flight) {
         // Retransmitted final flights cross the epoch boundary: CCS is sent
         // under the previous epoch and Finished under the newly activated one.
         // Keep both observations because their datagrams may arrive reordered.
         const uint16_t finished_epoch = static_cast<uint16_t>(epoch + 1);
         if(m_retransmitted_finished_epoch == finished_epoch) {
            m_retransmitted_finished_epoch.reset();
            if(m_retransmit_terminal_flight) {
               retransmit_last_flight();
            }
         } else {
            m_retransmitted_ccs_epoch = finished_epoch;
         }
      }
      return;
   }

   bool retransmit_response = false;

   while(record_len > 0) {
      if(record_len < DTLS_HANDSHAKE_HEADER_SIZE) {
         return;  // completely bogus? at least degenerate/weird
      }

      const Handshake_Type msg_type = static_cast<Handshake_Type>(record[0]);

      verify_is_expected_wire_handshake_type(msg_type);

      const size_t msg_len = load_be24(&record[1]);

      if(m_max_handshake_msg_size > 0 && msg_len > m_max_handshake_msg_size) {
         throw TLS_Exception(
            Alert::HandshakeFailure,
            Botan::fmt("Handshake message is {} bytes, policy maximum is {}", msg_len, m_max_handshake_msg_size));
      }

      const uint16_t message_seq = load_be<uint16_t>(&record[4], 0);
      const size_t fragment_offset = load_be24(&record[6]);
      const size_t fragment_length = load_be24(&record[9]);

      const size_t total_size = DTLS_HANDSHAKE_HEADER_SIZE + fragment_length;

      if(record_len < total_size) {
         throw Decoding_Error("Bad lengths in DTLS header");
      }

      retransmit_response |= process_handshake_fragment(&record[DTLS_HANDSHAKE_HEADER_SIZE],
                                                        fragment_length,
                                                        fragment_offset,
                                                        epoch,
                                                        msg_type,
                                                        msg_len,
                                                        message_seq,
                                                        retransmitted_flight);

      record += total_size;
      record_len -= total_size;
   }

   if(retransmit_response && (!m_finished || m_retransmit_terminal_flight)) {
      retransmit_last_flight();
   }
}

bool Datagram_Handshake_IO::process_handshake_fragment(const uint8_t fragment[],
                                                       size_t fragment_length,
                                                       size_t fragment_offset,
                                                       uint16_t epoch,
                                                       Handshake_Type msg_type,
                                                       size_t msg_length,
                                                       uint16_t message_seq,
                                                       bool retransmitted_flight) {
   // Bound the out-of-order reassembly window.
   constexpr uint16_t reassembly_window = 16;

   // An empty fragment for a non-empty message is garbage, just drop it.
   if(fragment_length == 0 && msg_length > 0) {
      return false;
   }

   if(message_seq < m_in_message_seq) {
      return process_previous_handshake_fragment(
         fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length, message_seq, retransmitted_flight);
   }

   // Beyond the reassembly window is not a retransmission of anything we
   // have seen, so it must not be able to pull a flight replay out of us.
   // Drop it silently: the sender has proven nothing at this point.
   if((message_seq - m_in_message_seq) >= reassembly_window) {
      return false;
   }

   /*
   RFC 6347 4.2.1 has the cookie exchange exist so that a server need not
   allocate state before the peer's reachability is proved. Until this
   endpoint commits to the handshake by sending a flight, the only message
   worth keeping is the ClientHello it is waiting for.

   Queueing anything else lets one spoofed datagram decide the handshake.
   A complete zero-length message parked in a future slot survives into the
   real handshake, where have_more_data() reads it as trailing handshake
   data and the server answers the legitimate client with a fatal alert.
   RFC 6347 4.2.2 permits queueing a future message but equally permits
   discarding it, and before a cookie there is nothing to weigh against
   the cost. Only future slots are dropped: a wrong message type at the
   sequence actually expected is a protocol error and has to be reported
   as one, which BoGo's WrongMessageType-ClientHello-DTLS checks.

   The count bounds it in the other direction: each accepted ClientHello
   advances the expected sequence and draws another HelloVerifyRequest, so
   without a limit that counter can be walked all the way around.
   */
   if(server_awaiting_first_flight() && ((msg_type != Handshake_Type::ClientHello && message_seq != m_in_message_seq) ||
                                         m_in_message_seq >= MAX_PRE_COMMIT_CLIENT_HELLOS)) {
      return false;
   }

   if(retransmitted_flight) {
      if(fragment_length == 0) {
         return false;
      }

      throw TLS_Exception(Alert::UnexpectedMessage, "Unexpected new DTLS handshake message");
   }

   // Charge the reassembly budget by bytes actually committed, not by
   // the claimed msg_length. Otherwise an attacker can lock the full
   // budget by sending small (e.g. fragment_length=1) fragments with
   // a large claimed msg_length, displacing legitimate handshake
   // messages.
   // Reserve headroom for the message actually being waited on. Otherwise
   // fragments for the fifteen slots beyond it can consume the whole
   // budget, after which every fragment of the expected message is
   // silently dropped and the handshake cannot proceed.
   const size_t ceiling = (message_seq == m_in_message_seq) ? m_max_pending_reassembly : m_max_pending_reassembly / 2;

   auto [it, inserted] = m_messages.try_emplace(message_seq);

   bool accepted = false;
   try {
      accepted = charged_add_fragment(
         it->second, ceiling, fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length);
   } catch(...) {
      if(inserted) {
         m_messages.erase(it);
      }
      throw;
   }

   if(!accepted && inserted) {
      m_messages.erase(it);
   }

   return false;
}

std::pair<Handshake_Type, std::vector<uint8_t>> Datagram_Handshake_IO::get_next_record(bool expecting_ccs,
                                                                                       size_t /*max_message_size*/) {
   // Expecting a message means the last flight is concluded
   if(!m_flights.rbegin()->empty()) {
      m_flights.emplace_back();
      m_flight_ccs.emplace_back();
   }

   if(expecting_ccs) {
      if(!m_messages.empty()) {
         const uint16_t current_epoch = m_messages.begin()->second.epoch();

         if(m_ccs_epochs.contains(current_epoch)) {
            return std::make_pair(Handshake_Type::HandshakeCCS, std::vector<uint8_t>());
         }
      }
      return std::make_pair(Handshake_Type::None, std::vector<uint8_t>());
   }

   auto i = m_messages.find(m_in_message_seq);

   if(i == m_messages.end() || !i->second.complete()) {
      // Nothing in sequence to make progress with. A buffered duplicate of an
      // earlier ClientHello is useful only here, to regenerate the stateless
      // cookie response. It deliberately does not take priority: delivering it
      // ahead of an in-sequence message makes that message look like trailing
      // data to the caller's have_more_data() check, which then aborts a
      // perfectly good handshake.
      if(m_retransmitted_client_hello.has_value() && m_retransmitted_client_hello->second.complete()) {
         auto duplicate = m_retransmitted_client_hello->second.message();
         m_last_client_hello_msg_seq = m_retransmitted_client_hello->first;
         release_reassembly_bytes(m_retransmitted_client_hello->second);
         m_retransmitted_client_hello.reset();
         return duplicate;
      }

      return std::make_pair(Handshake_Type::None, std::vector<uint8_t>());
   }

   m_in_message_seq += 1;
   m_any_message_delivered = true;

   auto result = i->second.message();

   if(result.first == Handshake_Type::ClientHello) {
      m_awaiting_cookie_client_hello = false;
      m_last_client_hello_msg_seq = static_cast<uint16_t>(m_in_message_seq - 1);

      // The ClientHello we were waiting for arrived, so a buffered duplicate of
      // an earlier one has nothing left to tell us.
      if(m_retransmitted_client_hello.has_value()) {
         release_reassembly_bytes(m_retransmitted_client_hello->second);
         m_retransmitted_client_hello.reset();
      }
   }

   // Free the reassembly buffer for this delivered slot and uncommit its
   // bytes against the cap. The entry itself stays in m_messages because
   // the expecting_ccs branch above uses m_messages.begin()->second.epoch()
   // as an epoch-0 sentinel; it only needs the metadata, not the buffers.
   release_reassembly_bytes(i->second);
   i->second.release_buffers();

   // May erase the entry i refers to, so nothing below may use it.
   prune_delivered_messages();

   return result;
}

void Datagram_Handshake_IO::prune_delivered_messages() {
   // Delivered slots are retained only so that the expecting_ccs branch above
   // can read an epoch from m_messages.begin(). Keeping one per delivered
   // message let unauthenticated input retain a map node apiece, none of it
   // charged against the reassembly budget, so all but the lowest are dropped.
   auto i = m_messages.begin();

   if(i == m_messages.end()) {
      return;
   }

   ++i;

   while(i != m_messages.end() && i->second.delivered()) {
      i = m_messages.erase(i);
   }
}

void Datagram_Handshake_IO::Handshake_Reassembly::release_buffers() {
   m_segments.clear();
   m_delivered = true;
}

void Datagram_Handshake_IO::Handshake_Reassembly::add_fragment(const uint8_t fragment[],
                                                               size_t fragment_length,
                                                               size_t fragment_offset,
                                                               uint16_t epoch,
                                                               Handshake_Type msg_type,
                                                               size_t msg_length) {
   /*
   A ClientHello begins a handshake, so nothing already buffered in its slot can
   belong to the same one. At epoch zero neither the buffered fragment nor the
   ClientHello is authenticated, and throwing means the *ClientHello* is what
   fails: anyone able to reach the address could plant one fragment before the
   cookie exchange and every later handshake attempt would die on it. Start over
   from the ClientHello instead, so a peer that retransmits can always make
   progress. An authenticated peer contradicting itself is still an error.
   */
   const auto restart_for_client_hello = [&] {
      m_epoch = epoch;
      m_msg_type = msg_type;
      m_msg_length = msg_length;
      m_bytes_received = 0;
      m_segments.clear();
   };

   const bool client_hello_supersedes_slot =
      (msg_type == Handshake_Type::ClientHello && epoch == 0 && m_epoch == 0 && !complete());

   if(m_msg_type == Handshake_Type::None) {
      // First fragment for this message_seq
      m_epoch = epoch;
      m_msg_type = msg_type;
      m_msg_length = msg_length;
   } else {
      // A delivered slot is a post-delivery sentinel kept for the expecting_ccs
      // branch; drop the fragment cheaply before running the per-fragment-header
      // consistency check. Otherwise a stray retransmission whose msg_length
      // field was rewritten in transit (or spoofed by an attacker for any
      // message_seq < m_in_message_seq) would throw Decoding_Error and tear down
      // the connection -- but post-delivery, no header check is meaningful since
      // the storage buffers are already released.
      if(m_delivered || complete()) {
         return;  // already have entire message, ignore this
      }

      if(msg_type != m_msg_type || msg_length != m_msg_length || epoch != m_epoch) {
         if(!client_hello_supersedes_slot) {
            throw Decoding_Error("Inconsistent values in fragmented DTLS handshake header");
         }
         restart_for_client_hello();
      }
   }

   if(fragment_offset > m_msg_length) {
      throw Decoding_Error("Fragment offset past end of message");
   }

   if(fragment_offset + fragment_length > m_msg_length) {
      throw Decoding_Error("Fragment overlaps past end of message");
   }

   if(fragment_length == 0) {
      return;
   }

   const size_t new_start = fragment_offset;
   const size_t new_end = fragment_offset + fragment_length;

   // Find the first existing segment that touches or overlaps [new_start,...].
   auto it = m_segments.lower_bound(new_start);
   if(it != m_segments.begin()) {
      auto prev = std::prev(it);
      if(prev->first + prev->second.size() >= new_start) {
         it = prev;
      }
   }

   // Walk forward through every segment that overlaps or is adjacent to the
   // (potentially-growing) merged span. RFC 6347 4.2.3: "DTLS implementations
   // MUST be able to handle overlapping fragment ranges." Requiring the
   // overlapping bytes to agree is ours, not the RFC's: disagreement means one
   // of the two copies is corrupt or forged.
   size_t merged_start = new_start;
   size_t merged_end = new_end;
   size_t existing_bytes = 0;
   const auto first_to_merge = it;
   while(it != m_segments.end() && it->first <= merged_end) {
      const size_t seg_start = it->first;
      const size_t seg_end = seg_start + it->second.size();

      const size_t ov_start = std::max(seg_start, new_start);
      const size_t ov_end = std::min(seg_end, new_end);
      for(size_t i = ov_start; i < ov_end; ++i) {
         if(it->second[i - seg_start] != fragment[i - new_start]) {
            if(!client_hello_supersedes_slot) {
               throw Decoding_Error("Inconsistent overlapping DTLS handshake fragment");
            }
            restart_for_client_hello();
            add_fragment(fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length);
            return;
         }
      }

      merged_start = std::min(merged_start, seg_start);
      merged_end = std::max(merged_end, seg_end);
      existing_bytes += it->second.size();
      ++it;
   }

   std::vector<uint8_t> merged(merged_end - merged_start);
   for(auto i = first_to_merge; i != it; ++i) {
      std::copy(i->second.begin(), i->second.end(), merged.begin() + (i->first - merged_start));
   }
   std::copy(fragment, fragment + fragment_length, merged.begin() + (new_start - merged_start));
   m_segments.erase(first_to_merge, it);
   m_segments.emplace(merged_start, std::move(merged));

   m_bytes_received += (merged_end - merged_start) - existing_bytes;
}

size_t Datagram_Handshake_IO::Handshake_Reassembly::charged_bytes_after_add(size_t fragment_length,
                                                                            size_t fragment_offset) const {
   // The early-out and merge-walk structure must match add_fragment above.
   if(m_delivered || complete() || fragment_length == 0) {
      return charged_bytes();
   }

   const size_t new_start = fragment_offset;
   const size_t new_end = fragment_offset + fragment_length;

   auto it = m_segments.lower_bound(new_start);
   if(it != m_segments.begin()) {
      auto prev = std::prev(it);
      if(prev->first + prev->second.size() >= new_start) {
         it = prev;
      }
   }

   size_t merged_start = new_start;
   size_t merged_end = new_end;
   size_t existing_bytes = 0;
   size_t merged_segments = 0;
   while(it != m_segments.end() && it->first <= merged_end) {
      merged_start = std::min(merged_start, it->first);
      merged_end = std::max(merged_end, it->first + it->second.size());
      existing_bytes += it->second.size();
      ++merged_segments;
      ++it;
   }

   const size_t merged_payload = m_bytes_received + (merged_end - merged_start) - existing_bytes;
   const size_t segments_after = m_segments.size() - merged_segments + 1;
   return merged_payload + SEGMENT_OVERHEAD * segments_after;
}

bool Datagram_Handshake_IO::Handshake_Reassembly::complete() const {
   // A delivered slot keeps its metadata but no longer has the bytes, so it
   // must not claim to be complete: message() would fail its own invariant and
   // have_more_data() would report trailing data that is not there. Reachable
   // once message_seq wraps back onto a slot already delivered.
   return (!m_delivered && m_msg_type != Handshake_Type::None && m_bytes_received == m_msg_length);
}

std::pair<Handshake_Type, std::vector<uint8_t>> Datagram_Handshake_IO::Handshake_Reassembly::message() const {
   if(!complete()) {
      throw Internal_Error("Datagram_Handshake_IO - message not complete");
   }

   if(m_msg_length == 0) {
      return std::make_pair(m_msg_type, std::vector<uint8_t>());
   }

   // Eager merging guarantees a single segment spanning [0, m_msg_length)
   // once bytes_received == m_msg_length.
   BOTAN_ASSERT_NOMSG(m_segments.size() == 1);
   const auto& only = *m_segments.begin();
   BOTAN_ASSERT_NOMSG(only.first == 0 && only.second.size() == m_msg_length);
   return std::make_pair(m_msg_type, only.second);
}

std::vector<uint8_t> Datagram_Handshake_IO::format_fragment(const uint8_t fragment[],
                                                            size_t frag_len,
                                                            uint32_t frag_offset,
                                                            uint32_t msg_len,
                                                            Handshake_Type type,
                                                            uint16_t msg_sequence) const {
   std::vector<uint8_t> send_buf(12 + frag_len);

   send_buf[0] = static_cast<uint8_t>(type);

   store_be24(&send_buf[1], msg_len);

   store_be(msg_sequence, &send_buf[4]);

   store_be24(&send_buf[6], frag_offset);
   store_be24(&send_buf[9], frag_len);

   if(frag_len > 0) {
      copy_mem(&send_buf[12], fragment, frag_len);
   }

   return send_buf;
}

std::vector<uint8_t> Datagram_Handshake_IO::format_w_seq(const std::vector<uint8_t>& msg,
                                                         Handshake_Type type,
                                                         uint16_t msg_sequence) const {
   return format_fragment(msg.data(), msg.size(), 0, static_cast<uint32_t>(msg.size()), type, msg_sequence);
}

std::vector<uint8_t> Datagram_Handshake_IO::format(const std::vector<uint8_t>& msg, Handshake_Type type) const {
   // Formats the message just delivered, so the guard is that one exists, not
   // that the counter is non-zero. Those differ once m_in_message_seq wraps,
   // which unauthenticated ClientHellos can drive: the cookie exchange is
   // supposed to be stateless but its pending state survives, and each attempt
   // advances the counter. The subtraction then wraps to 65535 of its own
   // accord, which is the right sequence number for that message.
   BOTAN_ASSERT_NOMSG(m_any_message_delivered);
   return format_w_seq(msg, type, static_cast<uint16_t>(m_in_message_seq - 1));
}

std::vector<uint8_t> Datagram_Handshake_IO::send(const Handshake_Message& msg) {
   return this->send_under_epoch(msg, m_seqs.current_write_epoch());
}

std::vector<uint8_t> Datagram_Handshake_IO::send_under_epoch(const Handshake_Message& msg, uint16_t epoch) {
   const std::vector<uint8_t> msg_bits = msg.serialize();
   const Handshake_Type msg_type = msg.type();

   if(msg_type == Handshake_Type::HandshakeCCS) {
      m_flight_ccs.rbegin()->emplace_back(m_flights.rbegin()->size(), epoch);
      m_send_hs(epoch, Record_Type::ChangeCipherSpec, msg_bits);
      return {};  // not included in handshake hashes
   } else if(msg_type == Handshake_Type::HelloVerifyRequest) {
      // RFC 6347 3.2.1: "Note that timeout and retransmission do not apply to
      // the HelloVerifyRequest, because this would require creating state on
      // the server." So it is not retained as a flight, and a repeated
      // ClientHello simply produces it again.
      //
      // RFC 6347 4.2.1, as corrected by erratum 5186, has it carry the
      // message_seq of the ClientHello that triggered it. Deriving that from the
      // outgoing counter instead breaks as soon as more than one cookie exchange
      // has happened on the association.
      const uint16_t msg_seq = m_last_client_hello_msg_seq.value_or(m_out_message_seq);

      // The ServerHello that follows a cookie exchange takes the next sequence
      // number (RFC 6347 4.2.2), but reissuing a HelloVerifyRequest for a
      // repeated ClientHello must not rewind the counter.
      m_out_message_seq = std::max<uint16_t>(m_out_message_seq, static_cast<uint16_t>(msg_seq + 1));

      m_awaiting_cookie_client_hello = true;
      send_message(msg_seq, epoch, msg_type, msg_bits);
      return {};
   }

   m_flights.rbegin()->push_back(m_out_message_seq);
   m_flight_data.emplace(m_out_message_seq, Message_Info(epoch, msg_type, msg_bits));

   m_out_message_seq += 1;
   m_last_write = m_steady_clock_ms();
   m_next_timeout = m_initial_timeout;
   // Sending a new flight is forward progress: reset the give-up counter so the
   // retransmission budget applies per flight, not across the whole handshake.
   m_retransmit_count = 0;

   return send_message(m_out_message_seq - 1, epoch, msg_type, msg_bits);
}

std::vector<uint8_t> Datagram_Handshake_IO::send_message(uint16_t msg_seq,
                                                         uint16_t epoch,
                                                         Handshake_Type msg_type,
                                                         const std::vector<uint8_t>& msg_bits) {
   auto no_fragment = format_w_seq(msg_bits, msg_type, msg_seq);

   /**
   * Since CBC suites are no longer supported/allowed in DTLS, the largest
   * possible ciphersuite overhead is 48 bytes, from NULL_WITH_SHA384. The AEAD
   * suites add at most 24 bytes (8 byte explicit nonce plus 16 byte tag).
   */
   const size_t ciphersuite_overhead = (epoch > 0) ? 48 : 0;

   if(no_fragment.size() + DTLS_HEADER_SIZE + ciphersuite_overhead <= m_mtu) {
      // We think the entire final packet will fit into the MTU
      m_send_hs(epoch, Record_Type::Handshake, no_fragment);
   } else {
      size_t frag_offset = 0;

      constexpr size_t DTLS_HANDSHAKE_OVERHEAD = DTLS_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE;

      if(m_mtu <= (DTLS_HANDSHAKE_OVERHEAD + ciphersuite_overhead)) {
         throw Invalid_Argument("DTLS MTU is too small to send headers");
      }

      const size_t max_rec_size = m_mtu - (DTLS_HANDSHAKE_OVERHEAD + ciphersuite_overhead);

      while(frag_offset != msg_bits.size()) {
         const size_t frag_len = std::min<size_t>(msg_bits.size() - frag_offset, max_rec_size);

         const std::vector<uint8_t> frag = format_fragment(&msg_bits[frag_offset],
                                                           frag_len,
                                                           static_cast<uint32_t>(frag_offset),
                                                           static_cast<uint32_t>(msg_bits.size()),
                                                           msg_type,
                                                           msg_seq);

         m_send_hs(epoch, Record_Type::Handshake, frag);

         frag_offset += frag_len;
      }
   }

   return no_fragment;
}

}  // namespace Botan::TLS
