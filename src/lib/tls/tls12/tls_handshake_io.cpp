/*
* TLS Handshake IO
* (C) 2012,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_io.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_handshake_msg.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>

namespace Botan::TLS {

namespace {

constexpr size_t DTLS_HANDSHAKE_HEADER_SIZE = 12;

// Bound on peer-cued flight replays when the policy leaves the timer's own retransmission
// count unlimited. Matches the default value of Policy::dtls_maximum_retransmissions.
constexpr size_t DEFAULT_PEER_REPLAY_BUDGET = 12;

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

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)

std::vector<uint8_t> Stream_Handshake_IO::start_with_client_hello_from_downgrade(
   const Handshake_Message& client_hello) {
   BOTAN_ARG_CHECK(client_hello.type() == Handshake_Type::ClientHello,
                   "Expected ClientHello message for TLS downgrade");

   // In TLS we don't have to update any internal state, we just need to
   // format the Client Hello message for absorption into the handshake hash.
   return format(client_hello.serialize(), client_hello.wire_type());
}

#endif

namespace {

size_t max_pending_reassembly(size_t policy_hs_max) {
   /*
   * Here we set arbitrary but probably more than sufficient bounds on the *overall*
   * allocation that is allowed across the entire handshake.
   *
   * If the policy set a limit on individual handshake message sizes, accept up to 4
   * times that for the whole handshake. This is more than generous considering most
   * handshake messages are fixed length or are relatively tightly bounded. The default
   * per-handshake message bound is 64 KiB so without application intervention this will
   * top out at 256 KiB for a handshake.
   *
   * If the application explicitly disables the per handshake message bound, still apply
   * an arbitrary upper bound of 16 MiB for the handshake.
   */
   constexpr size_t overall_cap = 16 * 1024 * 1024;

   if(policy_hs_max == 0 || policy_hs_max >= overall_cap / 4) {
      // If disabled or huge just take our max
      return overall_cap;
   } else {
      // Otherwise 4x the per-message max
      return policy_hs_max * 4;
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
                                             size_t max_handshake_msg_size) :
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
      m_max_pending_reassembly(max_pending_reassembly(m_max_handshake_msg_size)) {}

Protocol_Version Datagram_Handshake_IO::initial_record_version() const {
   return Protocol_Version::DTLS_V12;
}

std::optional<size_t> Datagram_Handshake_IO::last_completed_flight_index() const {
   // m_flights keeps an empty trailing slot while waiting for the peer, so the
   // last completed flight is normally the one before it.
   const size_t flight_idx = (m_flights.size() == 1) ? 0 : (m_flights.size() - 2);

   // A peer can ask us to replay a flight before we have sent one, eg
   // with a ClientHello whose message_seq is past the reassembly
   // window. In that case there is nothing to retransmit.
   if(m_flights[flight_idx].empty()) {
      return std::nullopt;
   }

   return flight_idx;
}

void Datagram_Handshake_IO::retransmit_last_flight() {
   if(const auto flight_idx = last_completed_flight_index()) {
      retransmit_flight(*flight_idx);
      m_last_write = m_steady_clock_ms();
   }
}

/*
* RFC 6347 4.2.4 gives the WAITING state a "read retransmit" transition that
* replays our flight when the peer retransmits theirs.
*
* The cue for it is unauthenticated epoch-zero data, so this deliberately is not
* retransmit_last_flight(). Re-anchoring m_last_write the way that does means a
* peer cueing faster than the timeout keeps next_retransmission_timeout() from
* ever expiring, so m_retransmit_count never advances and the handshake never
* gives up; and unbounded, each cue draws a whole flight toward whatever address
* the cue claims to come from.
*
* Spending the timer's own budget, reset by the same forward progress, caps a
* continuously cueing peer at doubling the flight traffic the handshake would
* emit anyway. Counting rather than rate limiting answers a legitimate peer's
* retransmit promptly, which BoGo's DTLS-Retransmit-Client-Basic requires.
*/
void Datagram_Handshake_IO::replay_last_flight_for_peer() {
   // An unset m_max_retransmissions means "retransmit on my own timer forever",
   // which is a different proposition from "replay whenever an unauthenticated
   // packet asks me to". This path is never unbounded, whatever the policy.
   const size_t bound = m_max_retransmissions.value_or(DEFAULT_PEER_REPLAY_BUDGET);

   if(m_peer_replay_count >= bound) {
      return;
   }

   if(const auto flight_idx = last_completed_flight_index()) {
      m_peer_replay_count += 1;
      retransmit_flight(*flight_idx);
   }
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
   // Future or incomplete fragments remain buffered, but only a complete
   // next-in-sequence message is trailing handshake data.
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

   // RFC 6347 4.2.4: "Once the messages have been sent, the implementation
   // then enters the FINISHED state if this is the last flight in the
   // handshake." Keep the flight for reactive replay when the peer
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
   // We allocate the entire block on the first fragment, so charge it against
   // the bound at that point. Later fragments must agree with the declared
   // length, so admission is decided once per slot and retransmissions are
   // never re-charged.
   if(!reassembly.initialized()) {
      if(m_pending_reassembly_bytes + msg_length > ceiling) {
         return false;
      }
      m_pending_reassembly_bytes += msg_length;
   }

   reassembly.add_fragment(fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length);
   return true;
}

void Datagram_Handshake_IO::release_reassembly_bytes(const Handshake_Reassembly& reassembly) {
   BOTAN_ASSERT_NOMSG(m_pending_reassembly_bytes >= reassembly.msg_length());
   m_pending_reassembly_bytes -= reassembly.msg_length();
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

      // RFC 6347 4.2.4 makes the terminal-flight sender "respond to a retransmit
      // of the peer's last flight with a retransmit of the last flight". Once our
      // handshake has completed, the peer's last flight is the one ending in its
      // Finished, never a ClientHello.
      if(m_finished) {
         return false;
      }

      return reassemble_retransmitted_fragment(
         fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length, message_seq);
   }

   // Only an association that has already completed its handshake answers a
   // retransmitted peer flight here.
   //
   // RFC 6347 4.2.4 also gives the WAITING state a "read retransmit" exit that
   // replays the outgoing flight immediately. Applying that while the handshake
   // is still pending misfires under fragment reordering: a late duplicate
   // fragment of an already-consumed message is indistinguishable from a
   // genuine retransmission, so the peer sees a flight replay it never asked
   // for (BoGo ReorderHandshakeFragments-Large). Recovery is left to the local
   // retransmission timer, which costs latency but cannot desynchronise a peer
   // that was not retransmitting. A retransmitted ClientHello is handled above,
   // because the stateless cookie response has no timer of its own.
   if(!retransmitted_flight) {
      return false;
   }

   // A genuine Finished follows a ChangeCipherSpec, so it is authenticated
   // under a non-zero epoch. An unauthenticated epoch-zero record claiming to
   // be one is spoofable off-path, and must not clear a ChangeCipherSpec we
   // have legitimately saved to pair against the real Finished.
   if(msg_type == Handshake_Type::Finished && epoch > 0 &&
      reassemble_retransmitted_fragment(
         fragment, fragment_length, fragment_offset, epoch, msg_type, msg_length, message_seq)) {
      // A final-flight retransmission includes CCS, but UDP may deliver its
      // records in either order. Wait until both have been observed.
      if(m_retransmitted_ccs_epoch == epoch) {
         m_retransmitted_ccs_epoch.reset();
         return true;
      }

      // Only the matching pair means anything, so a half seen for some other
      // epoch is stale. Leaving it set would keep this armed indefinitely for an
      // epoch an attacker chose, since epoch-zero CCS records are unauthenticated.
      m_retransmitted_ccs_epoch.reset();
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

   // A record under a non-zero epoch authenticated at the record layer, so the
   // peer is live and is who it claims to be. Restore the peer-cued replay
   // budget: RFC 6347 4.2.4 requires the terminal-flight sender to answer a
   // retransmit of the peer's last flight for as long as the association lasts,
   // and the retained IO never sends a new flight to reset the count otherwise.
   //
   // Only once our handshake has finished, though. While it is still pending,
   // forward progress already resets the count in send_under_epoch, so
   // restoring it here as well would let a peer alternate a cheap out-of-window
   // protected record with an epoch-zero cue to draw the pending flight without
   // bound.
   if(epoch > 0 && m_finished) {
      m_peer_replay_count = 0;
   }

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
               replay_last_flight_for_peer();
            }
         } else {
            m_retransmitted_finished_epoch.reset();
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

      // Bound the out-of-order reassembly window.
      constexpr uint16_t reassembly_window = 16;

      if(message_seq >= m_in_message_seq && (message_seq - m_in_message_seq) < reassembly_window) {
         // A wrapped counter would alias new messages onto long-delivered
         // sequence numbers. No legitimate handshake gets here, so go quiet.
         if(m_in_message_seq_wrapped) {
            record += total_size;
            record_len -= total_size;
            continue;
         }

         if(retransmitted_flight) {
            if(fragment_length == 0) {
               record += total_size;
               record_len -= total_size;
               continue;
            }

            throw TLS_Exception(Alert::UnexpectedMessage, "Unexpected new DTLS handshake message");
         }

         // An empty fragment for a non-empty message is garbage; drop it
         // before it can create and charge a reassembly slot.
         if(fragment_length == 0 && msg_len > 0) {
            record += total_size;
            record_len -= total_size;
            continue;
         }

         // Reserve headroom for the message actually being waited on. Otherwise
         // fragments for the fifteen slots beyond it can consume the whole
         // budget, after which every fragment of the expected message is
         // silently dropped and the handshake cannot proceed.
         const size_t ceiling =
            (message_seq == m_in_message_seq) ? m_max_pending_reassembly : m_max_pending_reassembly / 2;

         auto [it, inserted] = m_messages.try_emplace(message_seq);

         const bool accepted = charged_add_fragment(it->second,
                                                    ceiling,
                                                    &record[DTLS_HANDSHAKE_HEADER_SIZE],
                                                    fragment_length,
                                                    fragment_offset,
                                                    epoch,
                                                    msg_type,
                                                    msg_len);
         if(!accepted && inserted) {
            m_messages.erase(it);
         }
      } else if(message_seq < m_in_message_seq) {
         retransmit_response |= process_previous_handshake_fragment(&record[DTLS_HANDSHAKE_HEADER_SIZE],
                                                                    fragment_length,
                                                                    fragment_offset,
                                                                    epoch,
                                                                    msg_type,
                                                                    msg_len,
                                                                    message_seq,
                                                                    retransmitted_flight);
      }
      // else: beyond the reassembly window is not a retransmission of anything
      // we have seen, so it must not be able to pull a flight replay out of
      // us. Drop it silently: the sender has proven nothing at this point.

      record += total_size;
      record_len -= total_size;
   }

   if(retransmit_response && (!m_finished || m_retransmit_terminal_flight)) {
      replay_last_flight_for_peer();
   }
}

std::pair<Handshake_Type, std::vector<uint8_t>> Datagram_Handshake_IO::get_next_record(bool expecting_ccs,
                                                                                       size_t /*max_message_size*/) {
   // Expecting a message means the last flight is concluded
   if(!m_flights.rbegin()->empty()) {
      m_flights.emplace_back();
      m_flight_ccs.emplace_back();
   }

   if(expecting_ccs) {
      // CCS is expected under the epoch the peer's handshake messages have
      // been arriving on, and always follows at least one delivered message.
      if(m_first_delivered_epoch.has_value() && m_ccs_epochs.contains(*m_first_delivered_epoch)) {
         return std::make_pair(Handshake_Type::HandshakeCCS, std::vector<uint8_t>());
      }
      return std::make_pair(Handshake_Type::None, std::vector<uint8_t>());
   }

   if(m_retransmitted_client_hello.has_value() && m_retransmitted_client_hello->second.complete()) {
      auto result = m_retransmitted_client_hello->second.message();
      release_reassembly_bytes(m_retransmitted_client_hello->second);
      m_retransmitted_client_hello.reset();
      m_recreating_hello_verify_request = true;
      return result;
   }

   auto i = m_messages.find(m_in_message_seq);

   if(i == m_messages.end() || !i->second.complete()) {
      return std::make_pair(Handshake_Type::None, std::vector<uint8_t>());
   }

   m_in_message_seq += 1;
   if(m_in_message_seq == 0) {
      m_in_message_seq_wrapped = true;
   }

   if(!m_first_delivered_epoch.has_value()) {
      m_first_delivered_epoch = i->second.epoch();
   }

   auto result = i->second.message();

   if(result.first == Handshake_Type::ClientHello) {
      m_awaiting_cookie_client_hello = false;
   }

   release_reassembly_bytes(i->second);
   m_messages.erase(i);

   return result;
}

void Datagram_Handshake_IO::Handshake_Reassembly::add_fragment(const uint8_t fragment[],
                                                               size_t fragment_length,
                                                               size_t fragment_offset,
                                                               uint16_t epoch,
                                                               Handshake_Type msg_type,
                                                               size_t msg_length) {
   if(m_msg_type == Handshake_Type::None) {
      // First fragment for this message_seq
      m_epoch = epoch;
      m_msg_type = msg_type;
      m_msg_length = msg_length;
      m_message.resize(msg_length);
      m_received_mask.assign(msg_length, 0);
   } else {
      if(complete()) {
         // Ignore even if the header fields disagree: a stray or forged
         // retransmission must not tear down the connection once the
         // message has already been fully received.
         return;
      }

      if(msg_type != m_msg_type || msg_length != m_msg_length || epoch != m_epoch) {
         throw Decoding_Error("Inconsistent values in fragmented DTLS handshake header");
      }
   }

   if(fragment_offset > m_msg_length) {
      throw Decoding_Error("Fragment offset past end of message");
   }

   if(fragment_offset + fragment_length > m_msg_length) {
      throw Decoding_Error("Fragment overlaps past end of message");
   }

   BOTAN_ASSERT_NOMSG(m_received_mask.size() == m_msg_length);

   for(size_t i = 0; i != fragment_length; ++i) {
      const size_t off = fragment_offset + i;
      if(m_received_mask[off] != 0) {
         // RFC 6347 4.2.3 permits overlapping retransmissions, but the
         // overlapping bytes must agree.
         if(m_message[off] != fragment[i]) {
            throw Decoding_Error("Inconsistent overlapping DTLS handshake fragment");
         }
      } else {
         m_message[off] = fragment[i];
         m_received_mask[off] = 1;
         ++m_bytes_received;
      }
   }
}

bool Datagram_Handshake_IO::Handshake_Reassembly::complete() const {
   return (m_msg_type != Handshake_Type::None && m_bytes_received == m_msg_length);
}

std::pair<Handshake_Type, std::vector<uint8_t>> Datagram_Handshake_IO::Handshake_Reassembly::message() const {
   if(!complete()) {
      throw Internal_Error("Datagram_Handshake_IO - message not complete");
   }

   return std::make_pair(m_msg_type, m_message);
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
   // where the subtraction wraps to 65535 of its own accord, which is the
   // right sequence number for that message.
   BOTAN_ASSERT_NOMSG(m_first_delivered_epoch.has_value());
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
      // RFC 6347 3.2.1 explicitly excludes HelloVerifyRequest from timeout
      // retransmission. A repeated ClientHello recreates the response using
      // the original message sequence number without retaining a flight.
      const uint16_t msg_seq = m_recreating_hello_verify_request ? m_out_message_seq - 1 : m_out_message_seq++;
      m_awaiting_cookie_client_hello = true;
      m_recreating_hello_verify_request = false;
      send_message(msg_seq, epoch, msg_type, msg_bits);
      return {};
   }

   m_flights.rbegin()->push_back(m_out_message_seq);
   m_flight_data.insert_or_assign(m_out_message_seq, Message_Info(epoch, msg_type, msg_bits));

   m_out_message_seq += 1;
   m_last_write = m_steady_clock_ms();
   m_next_timeout = m_initial_timeout;
   // Sending a new flight is forward progress: reset the give-up counter so the
   // retransmission budget applies per flight, not across the whole handshake.
   m_retransmit_count = 0;
   m_peer_replay_count = 0;

   return send_message(m_out_message_seq - 1, epoch, msg_type, msg_bits);
}

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)

std::vector<uint8_t> Datagram_Handshake_IO::start_with_client_hello_from_downgrade(
   const Handshake_Message& client_hello) {
   BOTAN_ARG_CHECK(client_hello.type() == Handshake_Type::ClientHello,
                   "Expected ClientHello message for DTLS downgrade");
   BOTAN_STATE_CHECK(m_out_message_seq == 0);
   BOTAN_STATE_CHECK(m_seqs.current_write_epoch() == 0);
   return format_w_seq(client_hello.serialize(), client_hello.wire_type(), m_out_message_seq++);
}

#endif

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
