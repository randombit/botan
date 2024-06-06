/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <array>
#include <chrono>
#include <thread>

#if defined(BOTAN_HAS_TLS)

   #include <botan/credentials_manager.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_session_manager_hybrid.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/tls_session_manager_stateless.h>
   #include <botan/internal/fmt.h>

   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
      #include <botan/tls_session_manager_sqlite.h>
   #endif

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      #include <version>
      #if defined(__cpp_lib_filesystem)
         #include <filesystem>
      #endif
   #endif

// This file contains a number of `Botan::TLS::Version_Code::TLS_V**` protocol
// version specifications. This is to work around a compiler bug in GCC 11.3
// where `Botan::TLS::Protocol_Version::TLS_V12` would lead to an "Internal
// Compiler Error" when used in the affected context.
//
// TODO: remove the workaround once GCC 11 is not supported anymore.

namespace Botan_Tests {

class Test_Credentials_Manager : public Botan::Credentials_Manager {
   public:
      Botan::secure_vector<uint8_t> session_ticket_key() override {
         return Botan::hex_decode_locked("DEADFACECAFEBAAD");
      }
};

class Other_Test_Credentials_Manager : public Botan::Credentials_Manager {
   public:
      Botan::secure_vector<uint8_t> session_ticket_key() override {
         return Botan::hex_decode_locked("CAFEBAADFACEBABE");
      }
};

class Empty_Credentials_Manager : public Botan::Credentials_Manager {};

class Session_Manager_Callbacks : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t>) override { BOTAN_ASSERT_NOMSG(false); }

      void tls_record_received(uint64_t, std::span<const uint8_t>) override { BOTAN_ASSERT_NOMSG(false); }

      void tls_alert(Botan::TLS::Alert) override { BOTAN_ASSERT_NOMSG(false); }

      void tls_session_established(const Botan::TLS::Session_Summary&) override { BOTAN_ASSERT_NOMSG(false); }

      std::chrono::system_clock::time_point tls_current_timestamp() override {
         return std::chrono::system_clock::now() + std::chrono::hours(m_ticks);
      }

      void tick() { ++m_ticks; }

   private:
      uint64_t m_ticks = 0;
};

class Session_Manager_Policy : public Botan::TLS::Policy {
   public:
      std::chrono::seconds session_ticket_lifetime() const override { return std::chrono::minutes(30); }

      bool reuse_session_tickets() const override { return m_allow_session_reuse; }

      size_t maximum_session_tickets_per_client_hello() const override { return m_session_limit; }

      void set_session_limit(size_t l) { m_session_limit = l; }

      void set_allow_session_reuse(bool b) { m_allow_session_reuse = b; }

   private:
      size_t m_session_limit = 1000;  // basically 'no limit'
      bool m_allow_session_reuse = true;
};

namespace {

decltype(auto) random_id(Botan::RandomNumberGenerator& rng) {
   return rng.random_vec<Botan::TLS::Session_ID>(32);
}

decltype(auto) random_ticket(Botan::RandomNumberGenerator& rng) {
   return rng.random_vec<Botan::TLS::Session_Ticket>(32);
}

decltype(auto) random_opaque_handle(Botan::RandomNumberGenerator& rng) {
   return rng.random_vec<Botan::TLS::Opaque_Session_Handle>(32);
}

const Botan::TLS::Server_Information server_info("botan.randombit.net");

decltype(auto) default_session(Botan::TLS::Connection_Side side,
                               Botan::TLS::Callbacks& cbs,
                               Botan::TLS::Protocol_Version version = Botan::TLS::Protocol_Version::TLS_V12) {
   if(version.is_pre_tls_13()) {
      return Botan::TLS::Session(
         {}, version, 0x009C, side, true, true, {}, server_info, 0, cbs.tls_current_timestamp());
   } else {
   #if defined(BOTAN_HAS_TLS_13)
      return Botan::TLS::Session({},
                                 std::nullopt,
                                 0,
                                 std::chrono::seconds(1024),
                                 Botan::TLS::Protocol_Version::TLS_V13,
                                 Botan::TLS::Ciphersuite::from_name("AES_128_GCM_SHA256")->ciphersuite_code(),
                                 side,
                                 {},
                                 nullptr,
                                 server_info,
                                 cbs.tls_current_timestamp());
   #else
      throw Botan_Tests::Test_Error("TLS 1.3 is not available in this build");
   #endif
   }
}

using namespace std::literals;

std::vector<Test::Result> test_session_manager_in_memory() {
   auto rng = Test::new_shared_rng(__func__);

   const Botan::TLS::Session_ID default_id = random_id(*rng);

   std::optional<Botan::TLS::Session_Manager_In_Memory> mgr;

   Session_Manager_Callbacks cbs;
   Session_Manager_Policy plcy;

   return {
      Botan_Tests::CHECK("creation", [&](auto&) { mgr.emplace(rng, 5); }),

      Botan_Tests::CHECK("empty cache does not obtain anything",
                         [&](auto& result) {
                            result.confirm("no session found via server info",
                                           mgr->find(server_info, cbs, plcy).empty());

                            Botan::TLS::Session_ID mock_id = random_id(*rng);
                            auto mock_ticket = rng->random_vec<Botan::TLS::Session_Ticket>(128);

                            result.confirm("no session found via ID", !mgr->retrieve(mock_id, cbs, plcy));
                            result.confirm("no session found via ID", !mgr->retrieve(mock_ticket, cbs, plcy));
                         }),

      Botan_Tests::CHECK("clearing empty cache",
                         [&](auto& result) { result.test_eq("does not delete anything", mgr->remove_all(), 0); }),

      Botan_Tests::CHECK("establish new session",
                         [&](auto& result) {
                            auto handle =
                               mgr->establish(default_session(Botan::TLS::Connection_Side::Server, cbs), default_id);
                            if(result.confirm("establishment was successful", handle.has_value())) {
                               result.require("session id was set", handle->id().has_value());
                               result.confirm("session ticket was empty", !handle->ticket().has_value());
                               result.test_is_eq("session id is correct", handle->id().value(), default_id);
                            }
                         }),

      Botan_Tests::CHECK("obtain session from server info",
                         [&](auto& result) {
                            auto sessions = mgr->find(server_info, cbs, plcy);
                            if(result.confirm("session was found successfully", sessions.size() == 1)) {
                               result.test_is_eq("protocol version was echoed",
                                                 sessions[0].session.version(),
                                                 Botan::TLS::Protocol_Version(Botan::TLS::Version_Code::TLS_V12));
                               result.test_is_eq(
                                  "ciphersuite was echoed", sessions[0].session.ciphersuite_code(), uint16_t(0x009C));
                               result.test_is_eq("ID was echoed", sessions[0].handle.id().value(), default_id);
                               result.confirm("not a ticket", !sessions[0].handle.ticket().has_value());
                            }
                         }),

      Botan_Tests::CHECK("obtain session from ID",
                         [&](auto& result) {
                            auto session = mgr->retrieve(default_id, cbs, plcy);
                            if(result.confirm("session was found successfully", session.has_value())) {
                               result.test_is_eq("protocol version was echoed",
                                                 session->version(),
                                                 Botan::TLS::Protocol_Version(Botan::TLS::Version_Code::TLS_V12));
                               result.test_is_eq(
                                  "ciphersuite was echoed", session->ciphersuite_code(), uint16_t(0x009C));
                            }
                         }),

      Botan_Tests::CHECK("obtain session from ID disguised as opaque handle",
                         [&](auto& result) {
                            auto session = mgr->retrieve(Botan::TLS::Opaque_Session_Handle(default_id), cbs, plcy);
                            if(result.confirm("session was found successfully", session.has_value())) {
                               result.test_is_eq("protocol version was echoed",
                                                 session->version(),
                                                 Botan::TLS::Protocol_Version(Botan::TLS::Version_Code::TLS_V12));
                               result.test_is_eq(
                                  "ciphersuite was echoed", session->ciphersuite_code(), uint16_t(0x009C));
                            }
                         }),

      Botan_Tests::CHECK("obtain session from ticket == id does not work",
                         [&](auto& result) {
                            auto session = mgr->retrieve(Botan::TLS::Session_Ticket(default_id), cbs, plcy);
                            result.confirm("session was not found", !session.has_value());
                         }),

      Botan_Tests::CHECK("invalid ticket causes std::nullopt",
                         [&](auto& result) {
                            auto no_session = mgr->retrieve(random_ticket(*rng), cbs, plcy);
                            result.confirm("std::nullopt on bogus ticket", !no_session.has_value());
                         }),

      Botan_Tests::CHECK("invalid ID causes std::nullopt",
                         [&](auto& result) {
                            auto no_session = mgr->retrieve(random_id(*rng), cbs, plcy);
                            result.confirm("std::nullopt on bogus ID", !no_session.has_value());
                         }),

      Botan_Tests::CHECK("remove_all",
                         [&](auto& result) {
                            result.test_eq("removed one element", mgr->remove_all(), 1);
                            result.test_eq("should be empty now", mgr->remove_all(), 0);
                         }),

      Botan_Tests::CHECK("add session with ID",
                         [&](auto& result) {
                            Botan::TLS::Session_ID new_id = random_id(*rng);

                            mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs), new_id);
                            result.require("obtain via ID", mgr->retrieve(new_id, cbs, plcy).has_value());

                            auto sessions = mgr->find(server_info, cbs, plcy);
                            if(result.confirm("found via server info", sessions.size() == 1)) {
                               result.test_is_eq("protocol version was echoed",
                                                 sessions[0].session.version(),
                                                 Botan::TLS::Protocol_Version(Botan::TLS::Version_Code::TLS_V12));
                               result.test_is_eq(
                                  "ciphersuite was echoed", sessions[0].session.ciphersuite_code(), uint16_t(0x009C));
                               result.test_is_eq("ID was echoed", sessions[0].handle.id().value(), new_id);
                               result.confirm("ticket was not stored", !sessions[0].handle.ticket().has_value());
                            }

                            mgr->remove_all();
                         }),

      Botan_Tests::CHECK("add session with ticket",
                         [&](auto& result) {
                            Botan::TLS::Session_Ticket new_ticket = random_ticket(*rng);

                            mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs), new_ticket);
                            // cannot be obtained by (non-existent) ID or randomly generated ticket

                            auto sessions = mgr->find(server_info, cbs, plcy);
                            if(result.confirm("found via server info", sessions.size() == 1)) {
                               result.test_is_eq("protocol version was echoed",
                                                 sessions[0].session.version(),
                                                 Botan::TLS::Protocol_Version(Botan::TLS::Version_Code::TLS_V12));
                               result.test_is_eq(
                                  "ciphersuite was echoed", sessions[0].session.ciphersuite_code(), uint16_t(0x009C));
                               result.confirm("ID was not stored", !sessions[0].handle.id().has_value());
                               result.test_is_eq("ticket was echoed", sessions[0].handle.ticket().value(), new_ticket);
                            }

                            mgr->remove_all();
                         }),

      Botan_Tests::CHECK(
         "removing by ID or opaque handle",
         [&](auto& result) {
            Botan::TLS::Session_Manager_In_Memory local_mgr(rng);

            const auto new_session1 =
               local_mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs), default_id);
            const auto new_session2 = local_mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
            result.require(
               "saving worked",
               new_session1.has_value() && new_session1->id().has_value() && !new_session1->ticket().has_value());
            result.require(
               "saving worked",
               new_session2.has_value() && new_session2->id().has_value() && !new_session2->ticket().has_value());

            result.test_is_eq("can find via server info", local_mgr.find(server_info, cbs, plcy).size(), size_t(2));

            result.test_is_eq("one was deleted", local_mgr.remove(default_id), size_t(1));
            result.confirm("cannot obtain via default ID anymore",
                           !local_mgr.retrieve(default_id, cbs, plcy).has_value());
            result.test_is_eq(
               "can find less via server info", local_mgr.find(server_info, cbs, plcy).size(), size_t(1));

            result.test_is_eq("last one was deleted",
                              local_mgr.remove(Botan::TLS::Opaque_Session_Handle(new_session2->id().value())),
                              size_t(1));
            result.confirm("cannot obtain via ID anymore",
                           !local_mgr.retrieve(new_session2->id().value(), cbs, plcy).has_value());
            result.confirm("cannot find via server info", local_mgr.find(server_info, cbs, plcy).empty());
         }),

      Botan_Tests::CHECK(
         "removing by ticket or opaque handle",
         [&](auto& result) {
            Botan::TLS::Session_Manager_In_Memory local_mgr(rng);

            Botan::TLS::Session_Ticket ticket1 = random_ticket(*rng);
            Botan::TLS::Session_Ticket ticket2 = random_ticket(*rng);
            Botan::TLS::Session_Ticket ticket3 = random_ticket(*rng);

            local_mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), ticket1);
            local_mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), ticket2);
            local_mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), ticket3);
            result.test_is_eq(
               "can find them via server info ", local_mgr.find(server_info, cbs, plcy).size(), size_t(3));

            result.test_is_eq("remove one session by ticket", local_mgr.remove(ticket2), size_t(1));
            result.test_is_eq("can find two via server info", local_mgr.find(server_info, cbs, plcy).size(), size_t(2));

            result.test_is_eq("remove one session by opaque handle",
                              local_mgr.remove(Botan::TLS::Opaque_Session_Handle(ticket3.get())),
                              size_t(1));
            result.test_is_eq(
               "can find only one via server info", local_mgr.find(server_info, cbs, plcy).size(), size_t(1));
         }),

      Botan_Tests::CHECK(
         "session purging",
         [&](auto& result) {
            result.require("max sessions is 5", mgr->capacity() == 5);

            // fill the Session_Manager up fully
            std::vector<Botan::TLS::Session_Handle> handles;
            for(size_t i = 0; i < mgr->capacity(); ++i) {
               handles.push_back(
                  mgr->establish(default_session(Botan::TLS::Connection_Side::Server, cbs), random_id(*rng)).value());
            }

            for(size_t i = 0; i < handles.size(); ++i) {
               result.confirm("session still there", mgr->retrieve(handles[i], cbs, plcy).has_value());
            }

            // add one more session (causing a first purge to happen)
            handles.push_back(
               mgr->establish(default_session(Botan::TLS::Connection_Side::Server, cbs), random_id(*rng)).value());

            result.confirm("oldest session gone", !mgr->retrieve(handles[0], cbs, plcy).has_value());
            for(size_t i = 1; i < handles.size(); ++i) {
               result.confirm("session still there", mgr->retrieve(handles[i], cbs, plcy).has_value());
            }

            // remove a session to cause a 'gap' in the FIFO
            mgr->remove(handles[4]);
            result.confirm("oldest session gone", !mgr->retrieve(handles[0], cbs, plcy).has_value());
            result.confirm("deleted session gone", !mgr->retrieve(handles[4], cbs, plcy).has_value());
            for(size_t i = 1; i < handles.size(); ++i) {
               result.confirm("session still there", i == 4 || mgr->retrieve(handles[i], cbs, plcy).has_value());
            }

            // insert enough new sessions to fully purge the ones currently held
            for(size_t i = 0; i < mgr->capacity(); ++i) {
               handles.push_back(
                  mgr->establish(default_session(Botan::TLS::Connection_Side::Server, cbs), random_id(*rng)).value());
            }

            for(size_t i = 0; i < handles.size() - mgr->capacity(); ++i) {
               result.confirm("session gone", !mgr->retrieve(handles[i], cbs, plcy).has_value());
            }

            for(size_t i = handles.size() - mgr->capacity(); i < handles.size(); ++i) {
               result.confirm("session still there", mgr->retrieve(handles[i], cbs, plcy).has_value());
            }

            // clear it all out
            result.test_eq("rest of the sessions removed", mgr->remove_all(), size_t(5));
         }),
   };
}

std::vector<Test::Result> test_session_manager_choose_ticket() {
   #if defined(BOTAN_HAS_TLS_13)
   Session_Manager_Callbacks cbs;
   Session_Manager_Policy plcy;

   auto rng = Test::new_shared_rng(__func__);

   auto default_session = [&](const std::string& suite,
                              Botan::TLS::Callbacks& mycbs,
                              Botan::TLS::Protocol_Version version = Botan::TLS::Protocol_Version::TLS_V13) {
      return (version.is_pre_tls_13())
                ? Botan::TLS::Session({},
                                      version,
                                      Botan::TLS::Ciphersuite::from_name(suite)->ciphersuite_code(),
                                      Botan::TLS::Connection_Side::Server,
                                      true,
                                      true,
                                      {},
                                      server_info,
                                      0,
                                      mycbs.tls_current_timestamp())
                : Botan::TLS::Session({},
                                      std::nullopt,
                                      0,
                                      std::chrono::seconds(1024),
                                      version,
                                      Botan::TLS::Ciphersuite::from_name(suite)->ciphersuite_code(),
                                      Botan::TLS::Connection_Side::Server,
                                      {},
                                      nullptr,
                                      server_info,
                                      mycbs.tls_current_timestamp());
   };

   auto ticket = [&](std::span<const uint8_t> identity) {
      return Botan::TLS::PskIdentity(std::vector(identity.begin(), identity.end()), 0);
   };

   return {
      CHECK("empty manager has nothing to choose from",
            [&](auto& result) {
               Botan::TLS::Session_Manager_In_Memory mgr(rng);

               Botan::TLS::Session_Ticket random_session_ticket = random_ticket(*rng);

               result.confirm("empty ticket list, no session",
                              !mgr.choose_from_offered_tickets({}, "SHA-256", cbs, plcy).has_value());
               result.confirm(
                  "empty session manager, no session",
                  !mgr.choose_from_offered_tickets(std::vector{ticket(random_session_ticket)}, "SHA-256", cbs, plcy)
                      .has_value());
            }),

      CHECK("choose ticket by ID",
            [&](auto& result) {
               Botan::TLS::Session_Manager_In_Memory mgr(rng);
               std::vector<Botan::TLS::Session_Handle> handles;

               handles.push_back(mgr.establish(default_session("AES_128_GCM_SHA256", cbs)).value());
               handles.push_back(mgr.establish(default_session("AES_128_GCM_SHA256", cbs)).value());

               // choose from a list of tickets that contains only handles[0]
               auto session1 =
                  mgr.choose_from_offered_tickets(std::vector{ticket(handles[0].id().value())}, "SHA-256", cbs, plcy);
               result.require("ticket was chosen and produced a session (1)", session1.has_value());
               result.test_is_eq("chosen offset", session1->second, uint16_t(0));

               // choose from a list of tickets that contains only handles[1]
               auto session2 =
                  mgr.choose_from_offered_tickets(std::vector{ticket(handles[1].id().value())}, "SHA-256", cbs, plcy);
               result.require("ticket was chosen and produced a session (2)", session2.has_value());
               result.test_is_eq("chosen offset", session2->second, uint16_t(0));

               // choose from a list of tickets that contains a random ticket and handles[1]
               auto session3 = mgr.choose_from_offered_tickets(
                  std::vector{ticket(random_ticket(*rng)), ticket(handles[1].id().value())}, "SHA-256", cbs, plcy);
               result.require("ticket was chosen and produced a session (3)", session3.has_value());
               result.test_is_eq("chosen second offset", session3->second, uint16_t(1));
            }),

      CHECK("choose ticket by ticket",
            [&](auto& result) {
               auto creds = std::make_shared<Test_Credentials_Manager>();
               Botan::TLS::Session_Manager_Stateless mgr(creds, rng);
               std::vector<Botan::TLS::Session_Handle> handles;

               handles.push_back(mgr.establish(default_session("AES_128_GCM_SHA256", cbs)).value());
               handles.push_back(mgr.establish(default_session("AES_128_GCM_SHA256", cbs)).value());

               // choose from a list of tickets that contains only handles[0]
               auto session1 = mgr.choose_from_offered_tickets(
                  std::vector{ticket(handles[0].ticket().value())}, "SHA-256", cbs, plcy);
               result.require("ticket was chosen and produced a session (1)", session1.has_value());
               result.test_is_eq("chosen offset", session1->second, uint16_t(0));

               // choose from a list of tickets that contains only handles[1]
               auto session2 = mgr.choose_from_offered_tickets(
                  std::vector{ticket(handles[1].ticket().value())}, "SHA-256", cbs, plcy);
               result.require("ticket was chosen and produced a session (2)", session2.has_value());
               result.test_is_eq("chosen offset", session2->second, uint16_t(0));

               // choose from a list of tickets that contains a random ticket and handles[1]
               auto session3 = mgr.choose_from_offered_tickets(
                  std::vector{ticket(random_ticket(*rng)), ticket(handles[1].ticket().value())}, "SHA-256", cbs, plcy);
               result.require("ticket was chosen and produced a session (3)", session3.has_value());
               result.test_is_eq("chosen second offset", session3->second, uint16_t(1));
            }),

      CHECK("choose ticket based on requested hash function",
            [&](auto& result) {
               auto creds = std::make_shared<Test_Credentials_Manager>();
               Botan::TLS::Session_Manager_Stateless mgr(creds, rng);
               std::vector<Botan::TLS::Session_Handle> handles;

               handles.push_back(mgr.establish(default_session("AES_128_GCM_SHA256", cbs)).value());
               handles.push_back(mgr.establish(default_session("AES_256_GCM_SHA384", cbs)).value());

               auto session = mgr.choose_from_offered_tickets(std::vector{ticket(random_ticket(*rng)),
                                                                          ticket(handles[0].ticket().value()),
                                                                          ticket(handles[1].ticket().value())},
                                                              "SHA-384",
                                                              cbs,
                                                              plcy);
               result.require("ticket was chosen and produced a session", session.has_value());
               result.test_is_eq("chosen second offset", session->second, uint16_t(2));
            }),

      CHECK("choose ticket based on protocol version",
            [&](auto& result) {
               auto creds = std::make_shared<Test_Credentials_Manager>();
               Botan::TLS::Session_Manager_Stateless mgr(creds, rng);
               std::vector<Botan::TLS::Session_Handle> handles;

               handles.push_back(
                  mgr.establish(default_session("AES_128_GCM_SHA256", cbs, Botan::TLS::Version_Code::TLS_V12)).value());
               handles.push_back(
                  mgr.establish(default_session("AES_128_GCM_SHA256", cbs, Botan::TLS::Version_Code::TLS_V13)).value());

               auto session = mgr.choose_from_offered_tickets(std::vector{ticket(random_ticket(*rng)),
                                                                          ticket(handles[0].ticket().value()),
                                                                          ticket(handles[1].ticket().value())},
                                                              "SHA-256",
                                                              cbs,
                                                              plcy);
               result.require("ticket was chosen and produced a session", session.has_value());
               result.test_is_eq("chosen second offset (TLS 1.3 ticket)", session->second, uint16_t(2));
            }),
   };
   #else
   return {};
   #endif
}

std::vector<Test::Result> test_session_manager_stateless() {
   auto creds = std::make_shared<Test_Credentials_Manager>();

   auto rng = Test::new_shared_rng(__func__);

   Botan::TLS::Session_Manager_Stateless mgr(creds, rng);

   Session_Manager_Callbacks cbs;
   Session_Manager_Policy plcy;

   return {
      Botan_Tests::CHECK("establish with default parameters",
                         [&](auto& result) {
                            result.confirm("will emit tickets", mgr.emits_session_tickets());
                            auto ticket = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
                            result.confirm("returned ticket", ticket.has_value() && ticket->is_ticket());
                         }),

      Botan_Tests::CHECK("establish with disabled tickets",
                         [&](auto& result) {
                            result.confirm("will emit tickets", mgr.emits_session_tickets());
                            auto ticket = mgr.establish(
                               default_session(Botan::TLS::Connection_Side::Server, cbs), std::nullopt, true);
                            result.confirm("returned std::nullopt", !ticket.has_value());
                         }),

      Botan_Tests::CHECK(
         "establish without ticket key in credentials manager",
         [&](auto& result) {
            Botan::TLS::Session_Manager_Stateless local_mgr(std::make_shared<Empty_Credentials_Manager>(), rng);

            result.confirm("won't emit tickets", !local_mgr.emits_session_tickets());
            auto ticket = local_mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
            result.confirm("returned std::nullopt", !ticket.has_value());
         }),

      Botan_Tests::CHECK("retrieve via ticket",
                         [&](auto& result) {
                            auto ticket1 = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
                            auto ticket2 = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
                            result.require("tickets created successfully", ticket1.has_value() && ticket2.has_value());

                            Botan::TLS::Session_Manager_Stateless local_mgr(creds, rng);
                            result.confirm("can retrieve ticket 1",
                                           mgr.retrieve(ticket1.value(), cbs, plcy).has_value());
                            result.confirm("can retrieve ticket 2 from different manager but sam credentials",
                                           local_mgr.retrieve(ticket2.value(), cbs, plcy).has_value());
                         }),

      Botan_Tests::CHECK("retrieve via ID does not work",
                         [&](auto& result) {
                            auto ticket1 = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
                            result.require("tickets created successfully", ticket1.has_value() && ticket1.has_value());

                            result.confirm("retrieval by ID does not work",
                                           !mgr.retrieve(random_id(*rng), cbs, plcy).has_value());
                         }),

      Botan_Tests::CHECK("retrieve via opaque handle does work",
                         [&](auto& result) {
                            auto ticket1 = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
                            result.require("tickets created successfully", ticket1.has_value() && ticket1.has_value());

                            result.confirm("retrieval by opaque handle",
                                           mgr.retrieve(ticket1->opaque_handle(), cbs, plcy).has_value());
                         }),

      Botan_Tests::CHECK(
         "no retrieve without or with wrong ticket key",
         [&](auto& result) {
            auto ticket1 = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
            result.require("tickets created successfully", ticket1.has_value() && ticket1.has_value());

            Botan::TLS::Session_Manager_Stateless local_mgr1(std::make_shared<Empty_Credentials_Manager>(), rng);

            Botan::TLS::Session_Manager_Stateless local_mgr2(std::make_shared<Other_Test_Credentials_Manager>(), rng);

            result.confirm("no successful retrieval (without key)",
                           !local_mgr1.retrieve(ticket1.value(), cbs, plcy).has_value());
            result.confirm("no successful retrieval (with wrong key)",
                           !local_mgr2.retrieve(ticket1.value(), cbs, plcy).has_value());
            result.confirm("successful retrieval", mgr.retrieve(ticket1.value(), cbs, plcy).has_value());
         }),

      Botan_Tests::CHECK(
         "Clients cannot be stateless",
         [&](auto& result) {
            result.test_throws("::store() does not work with ID", [&] {
               mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), random_id(*rng));
            });
            result.test_throws("::store() does not work with ticket", [&] {
               mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), random_ticket(*rng));
            });
            result.test_throws("::store() does not work with opaque handle", [&] {
               mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), random_opaque_handle(*rng));
            });

            auto ticket1 = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
            result.require("tickets created successfully", ticket1.has_value() && ticket1.has_value());
            result.confirm("finding tickets does not work", mgr.find(server_info, cbs, plcy).empty());
         }),

      Botan_Tests::CHECK(
         "remove is a NOOP",
         [&](auto& result) {
            auto ticket1 = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
            result.require("tickets created successfully", ticket1.has_value() && ticket1.has_value());

            result.test_is_eq("remove the ticket", mgr.remove(ticket1.value()), size_t(0));
            result.confirm("successful retrieval 1", mgr.retrieve(ticket1.value(), cbs, plcy).has_value());

            result.test_is_eq("remove the ticket", mgr.remove_all(), size_t(0));
            result.confirm("successful retrieval 1", mgr.retrieve(ticket1.value(), cbs, plcy).has_value());
         }),

      Botan_Tests::CHECK(
         "retrieval via ticket reconstructs the start_time stamp",
         [&](auto& result) {
            auto session_before = default_session(Botan::TLS::Connection_Side::Server, cbs);
            auto ticket = mgr.establish(session_before);
            result.require("got a ticket", ticket.has_value() && ticket->is_ticket());
            auto session_after = mgr.retrieve(ticket.value(), cbs, plcy);
            result.require("got the session back", session_after.has_value());

            result.test_is_eq(
               "timestamps match",
               std::chrono::duration_cast<std::chrono::seconds>(session_before.start_time().time_since_epoch()).count(),
               std::chrono::duration_cast<std::chrono::seconds>(session_after->start_time().time_since_epoch())
                  .count());
         }),
   };
}

std::vector<Test::Result> test_session_manager_hybrid() {
   auto rng = Test::new_shared_rng(__func__);

   auto creds = std::make_shared<Test_Credentials_Manager>();
   Session_Manager_Callbacks cbs;
   Session_Manager_Policy plcy;

   // Runs the passed-in hybrid manager test lambdas for all available stateful
   // managers. The `make_manager()` helper is passed into the test code and
   // transparently constructs a hybrid manager with the respective internal
   // stateful manager.
   auto CHECK_all = [&](const std::string& name, auto lambda) -> std::vector<Test::Result> {
      std::vector<std::pair<std::string, std::function<std::unique_ptr<Botan::TLS::Session_Manager>()>>>
         stateful_manager_factories = {
            {"In Memory",
             [&rng]() -> std::unique_ptr<Botan::TLS::Session_Manager> {
                return std::make_unique<Botan::TLS::Session_Manager_In_Memory>(rng, 10);
             }},
   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
            {"SQLite",
             [&rng]() -> std::unique_ptr<Botan::TLS::Session_Manager> {
                return std::make_unique<Botan::TLS::Session_Manager_SQLite>(
                   "secure_pw", rng, Test::temp_file_name("tls_session_manager_sqlite"), 10);
             }},
   #endif
         };

      std::vector<Test::Result> results;
      using namespace std::placeholders;
      for(auto& factory_and_name : stateful_manager_factories) {
         auto& stateful_manager_name = factory_and_name.first;
         auto& stateful_manager_factory = factory_and_name.second;
         auto make_manager = [stateful_manager_factory, &creds, &rng](bool prefer_tickets) {
            return Botan::TLS::Session_Manager_Hybrid(stateful_manager_factory(), creds, rng, prefer_tickets);
         };

         auto nm = Botan::fmt("{} ({})", name, stateful_manager_name);
         auto fn = std::bind(lambda, make_manager, _1);
         results.push_back(Botan_Tests::CHECK(nm.c_str(), fn));
      }
      return results;
   };

   return Test::flatten_result_lists({
      CHECK_all("ticket vs ID preference in establishment",
                [&](auto make_manager, auto& result) {
                   auto mgr_prefers_tickets = make_manager(true);
                   auto ticket1 =
                      mgr_prefers_tickets.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
                   result.confirm("emits a ticket", ticket1.has_value() && ticket1->is_ticket());

                   auto mgr_prefers_ids = make_manager(false);
                   auto ticket2 = mgr_prefers_ids.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
                   result.confirm("emits an ID", ticket2.has_value() && ticket2->is_id());

                   auto ticket3 = mgr_prefers_ids.establish(default_session(Botan::TLS::Connection_Side::Server, cbs),
                                                            std::nullopt,
                                                            true /* TLS 1.2 no ticket support */);
                   result.confirm("emits an ID", ticket3.has_value() && ticket3->is_id());

                   auto ticket4 = mgr_prefers_ids.establish(default_session(Botan::TLS::Connection_Side::Server, cbs),
                                                            std::nullopt,
                                                            true /* TLS 1.2 no ticket support */);
                   result.confirm("emits an ID", ticket4.has_value() && ticket4->is_id());
                }),

      CHECK_all("ticket vs ID preference in retrieval",
                [&](auto make_manager, auto& result) {
                   auto mgr_prefers_tickets = make_manager(true);
                   auto mgr_prefers_ids = make_manager(false);

                   auto id1 = mgr_prefers_tickets.underlying_stateful_manager()->establish(
                      default_session(Botan::TLS::Connection_Side::Server, cbs));
                   auto id2 = mgr_prefers_ids.underlying_stateful_manager()->establish(
                      default_session(Botan::TLS::Connection_Side::Server, cbs));
                   auto ticket =
                      mgr_prefers_tickets.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));

                   result.require("establishments worked", id1.has_value() && id2.has_value() && ticket.has_value());

                   result.confirm("mgr1 + ID1", mgr_prefers_tickets.retrieve(id1.value(), cbs, plcy).has_value());
                   result.confirm("mgr1 + ID2", !mgr_prefers_tickets.retrieve(id2.value(), cbs, plcy).has_value());
                   result.confirm("mgr2 + ID1", !mgr_prefers_ids.retrieve(id1.value(), cbs, plcy).has_value());
                   result.confirm("mgr2 + ID2", mgr_prefers_ids.retrieve(id2.value(), cbs, plcy).has_value());
                   result.confirm("mgr1 + ticket", mgr_prefers_tickets.retrieve(ticket.value(), cbs, plcy).has_value());
                   result.confirm("mgr2 + ticket", mgr_prefers_ids.retrieve(ticket.value(), cbs, plcy).has_value());
                }),

      CHECK_all("no session tickets if hybrid manager cannot create them",
                [&](auto make_manager, auto& result) {
                   Botan::TLS::Session_Manager_Hybrid empty_mgr(
                      std::make_unique<Botan::TLS::Session_Manager_In_Memory>(rng, 10),
                      std::make_shared<Empty_Credentials_Manager>(),
                      rng);
                   auto mgr_prefers_tickets = make_manager(true);
                   auto mgr_prefers_ids = make_manager(false);

                   result.confirm("does not emit tickets", !empty_mgr.emits_session_tickets());
                   result.confirm("does emit tickets 1", mgr_prefers_tickets.emits_session_tickets());
                   result.confirm("does emit tickets 2", mgr_prefers_ids.emits_session_tickets());
                }),
   });
}

namespace {

class Temporary_Database_File {
   private:
      std::string m_temp_file;

   public:
      Temporary_Database_File(const std::string& db_file) : m_temp_file(Test::data_file_as_temporary_copy(db_file)) {
         if(m_temp_file.empty()) {
            throw Test_Error("Failed to create temporary database file");
         }
      }

      ~Temporary_Database_File() {
   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && defined(__cpp_lib_filesystem)
         if(!m_temp_file.empty()) {
            std::filesystem::remove(m_temp_file);
         }
   #endif
      }

      const std::string& get() const { return m_temp_file; }

      Temporary_Database_File(const Temporary_Database_File&) = delete;
      Temporary_Database_File& operator=(const Temporary_Database_File&) = delete;
      Temporary_Database_File(Temporary_Database_File&&) = delete;
      Temporary_Database_File& operator=(Temporary_Database_File&&) = delete;
};

}  // namespace

std::vector<Test::Result> test_session_manager_sqlite() {
   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
   auto rng = Test::new_shared_rng(__func__);
   Session_Manager_Callbacks cbs;
   Session_Manager_Policy plcy;

   return {
      Botan_Tests::CHECK(
         "migrate session database scheme (purges database)",
         [&](auto& result) {
            Temporary_Database_File dbfile("tls-sessions/botan-2.19.3.sqlite");

            // legacy database (encrypted with 'thetruthisoutthere') containing:
            //    $ sqlite3 src/tests/data/tls-sessions/botan-2.19.3.sqlite  'SELECT * FROM tls_sessions;'
            //    63C136FAD49F05A184F910FD6568A3884164216C11E41CEBFDCD149AF66C1714|1673606906|cloudflare.com|443|...
            //    63C137030387E4A6CDAD303CCB1F53884944FDE5B4EDD91E6FCF74DCB033DCEB|1673606915|randombit.net|443|...
            Botan::TLS::Session_Manager_SQLite legacy_db("thetruthisoutthere", rng, dbfile.get());

            result.confirm("Session_ID for randombit.net is gone",
                           !legacy_db
                               .retrieve(Botan::TLS::Session_ID(Botan::hex_decode(
                                            "63C137030387E4A6CDAD303CCB1F53884944FDE5B4EDD91E6FCF74DCB033DCEB")),
                                         cbs,
                                         plcy)
                               .has_value());
            result.confirm("Session_ID for cloudflare.com is gone",
                           !legacy_db
                               .retrieve(Botan::TLS::Session_ID(Botan::hex_decode(
                                            "63C136FAD49F05A184F910FD6568A3884164216C11E41CEBFDCD149AF66C1714")),
                                         cbs,
                                         plcy)
                               .has_value());
            result.confirm("no more session for randombit.net",
                           legacy_db.find(Botan::TLS::Server_Information("randombit.net", 443), cbs, plcy).empty());
            result.confirm("no more session for cloudflare.com",
                           legacy_db.find(Botan::TLS::Server_Information("cloudflare.com", 443), cbs, plcy).empty());

            result.test_is_eq("empty database won't get more empty", legacy_db.remove_all(), size_t(0));
         }),

      Botan_Tests::CHECK("clearing empty database",
                         [&](auto& result) {
                            Botan::TLS::Session_Manager_SQLite mgr(
                               "thetruthisoutthere", rng, Test::temp_file_name("empty.sqlite"));
                            result.test_eq("does not delete anything", mgr.remove_all(), 0);
                         }),

      Botan_Tests::CHECK(
         "establish new session",
         [&](auto& result) {
            Botan::TLS::Session_Manager_SQLite mgr(
               "thetruthisoutthere", rng, Test::temp_file_name("new_session.sqlite"));
            auto some_random_id = random_id(*rng);
            auto some_random_handle =
               mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs), some_random_id);
            result.require("establishment was successful", some_random_handle.has_value());
            result.require("session id was set", some_random_handle->id().has_value());
            result.test_is_eq("session id is correct", some_random_handle->id().value(), some_random_id);

            auto some_virtual_handle = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
            result.require("establishment was successful", some_virtual_handle.has_value());
            result.require("session id was set", some_virtual_handle->id().has_value());
         }),

      Botan_Tests::CHECK(
         "retrieve session by ID",
         [&](auto& result) {
            Botan::TLS::Session_Manager_SQLite mgr(
               "thetruthisoutthere", rng, Test::temp_file_name("retrieve_by_id.sqlite"));
            auto some_random_id = random_id(*rng);
            auto some_random_handle =
               mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs), some_random_id);
            auto some_virtual_handle = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));

            result.require("establishment was successful", some_random_handle->is_id() && some_virtual_handle->is_id());

            auto session1 = mgr.retrieve(some_random_handle.value(), cbs, plcy);
            if(result.confirm("found session by user-provided ID", session1.has_value())) {
               result.test_is_eq("protocol version was echoed",
                                 session1->version(),
                                 Botan::TLS::Protocol_Version(Botan::TLS::Version_Code::TLS_V12));
               result.test_is_eq("ciphersuite was echoed", session1->ciphersuite_code(), uint16_t(0x009C));
            }

            auto session2 = mgr.retrieve(some_virtual_handle.value(), cbs, plcy);
            if(result.confirm("found session by manager-generated ID", session2.has_value())) {
               result.test_is_eq("protocol version was echoed",
                                 session2->version(),
                                 Botan::TLS::Protocol_Version(Botan::TLS::Version_Code::TLS_V12));
               result.test_is_eq("ciphersuite was echoed", session2->ciphersuite_code(), uint16_t(0x009C));
            }

            auto session3 = mgr.retrieve(random_id(*rng), cbs, plcy);
            result.confirm("random ID creates empty result", !session3.has_value());
         }),

      Botan_Tests::CHECK(
         "retrieval via ticket creates empty result",
         [&](auto& result) {
            Botan::TLS::Session_Manager_SQLite mgr(
               "thetruthisoutthere", rng, Test::temp_file_name("retrieve_by_ticket.sqlite"));
            auto some_random_handle =
               mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs), random_id(*rng));
            auto some_virtual_handle = mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs));

            result.confirm("std::nullopt on random ticket", !mgr.retrieve(random_ticket(*rng), cbs, plcy).has_value());
         }),

      Botan_Tests::CHECK("storing sessions and finding them by server info",
                         [&](auto& result) {
                            Botan::TLS::Session_Manager_SQLite mgr(
                               "thetruthisoutthere", rng, Test::temp_file_name("store_and_find.sqlite"));
                            auto id = random_id(*rng);
                            auto ticket = random_ticket(*rng);
                            mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), id);
                            mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), ticket);

                            auto found_sessions = mgr.find(server_info, cbs, plcy);
                            if(result.test_is_eq("found both sessions", found_sessions.size(), size_t(2))) {
                               for(const auto& [session, handle] : found_sessions) {
                                  result.confirm("ID matches", !handle.is_id() || handle.id().value() == id);
                                  result.confirm("ticket matches",
                                                 !handle.is_ticket() || handle.ticket().value() == ticket);
                               }
                            }
                         }),

      Botan_Tests::CHECK(
         "removing sessions",
         [&](auto& result) {
            Botan::TLS::Session_Manager_SQLite mgr("thetruthisoutthere", rng, Test::temp_file_name("remove.sqlite"));
            auto id = random_id(*rng);
            auto ticket = random_ticket(*rng);
            mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), id);
            mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), ticket);
            mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), random_id(*rng));
            mgr.store(default_session(Botan::TLS::Connection_Side::Client, cbs), random_ticket(*rng));

            result.test_is_eq("deletes one session by ID", mgr.remove(id), size_t(1));
            result.test_is_eq("deletes one session by ticket", mgr.remove(ticket), size_t(1));

            auto found_sessions = mgr.find(server_info, cbs, plcy);
            if(result.test_is_eq("found some other sessions", found_sessions.size(), size_t(2))) {
               for(const auto& [session, handle] : found_sessions) {
                  result.confirm("ID does not match", !handle.is_id() || handle.id().value() != id);
                  result.confirm("ticket does not match", !handle.is_ticket() || handle.ticket().value() != ticket);
               }
            }

            result.test_is_eq("removing the rest of the sessions", mgr.remove_all(), size_t(2));
         }),

      Botan_Tests::CHECK(
         "old sessions are purged when needed",
         [&](auto& result) {
            Botan::TLS::Session_Manager_SQLite mgr(
               "thetruthisoutthere", rng, Test::temp_file_name("purging.sqlite"), 1);

            std::vector<Botan::TLS::Session_ID> ids = {random_id(*rng), random_id(*rng), random_id(*rng)};
            mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs), ids[0]);
            result.require("new ID exists", mgr.retrieve(ids[0], cbs, plcy).has_value());

            // Session timestamps are saved with second-resolution. If more than
            // one session has the same (coarse) timestamp it is undefined which
            // will be purged first. The clock tick ensures that session's
            // timestamps are unique.
            cbs.tick();
            mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs), ids[1]);
            result.require("first ID is gone", !mgr.retrieve(ids[0], cbs, plcy).has_value());
            result.require("new ID exists", mgr.retrieve(ids[1], cbs, plcy).has_value());

            cbs.tick();
            mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs), ids[2]);
            result.require("second ID is gone", !mgr.retrieve(ids[1], cbs, plcy).has_value());
            result.require("new ID exists", mgr.retrieve(ids[2], cbs, plcy).has_value());

            result.test_is_eq("only one entry exists", mgr.remove_all(), size_t(1));
         }),

      Botan_Tests::CHECK("session purging can be disabled",
                         [&](auto& result) {
                            Botan::TLS::Session_Manager_SQLite mgr(
                               "thetruthisoutthere", rng, Test::temp_file_name("purging.sqlite"), 0 /* no pruning! */);

                            for(size_t i = 0; i < 25; ++i) {
                               mgr.establish(default_session(Botan::TLS::Connection_Side::Server, cbs),
                                             random_id(*rng));
                            }

                            result.test_is_eq("no entries were purged along the way", mgr.remove_all(), size_t(25));
                         }),
   };
   #else
   return {};
   #endif
}

std::vector<Test::Result> tls_session_manager_expiry() {
   auto rng = Test::new_shared_rng(__func__);
   Session_Manager_Callbacks cbs;
   Session_Manager_Policy plcy;

   auto CHECK_all = [&](const std::string& name, auto lambda) -> std::vector<Test::Result> {
      std::vector<std::pair<std::string, std::function<std::unique_ptr<Botan::TLS::Session_Manager>()>>>
         stateful_manager_factories = {
            {"In Memory",
             [&rng]() -> std::unique_ptr<Botan::TLS::Session_Manager> {
                return std::make_unique<Botan::TLS::Session_Manager_In_Memory>(rng, 10);
             }},
            {"Stateless",
             [&]() -> std::unique_ptr<Botan::TLS::Session_Manager> {
                return std::make_unique<Botan::TLS::Session_Manager_Stateless>(
                   std::make_shared<Test_Credentials_Manager>(), rng);
             }},
   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
            {"SQLite",
             [&rng]() -> std::unique_ptr<Botan::TLS::Session_Manager> {
                return std::make_unique<Botan::TLS::Session_Manager_SQLite>(
                   "secure_pw", rng, Test::temp_file_name("tls_session_manager_sqlite"), 10);
             }},
   #endif
         };

      std::vector<Test::Result> results;
      results.reserve(stateful_manager_factories.size());
      using namespace std::placeholders;
      for(auto& [sub_name, factory] : stateful_manager_factories) {
         auto nm = Botan::fmt("{} ({})", name, sub_name);
         auto fn = std::bind(lambda, sub_name, factory, _1);
         results.push_back(Botan_Tests::CHECK(nm.c_str(), fn));
      }
      return results;
   };

   return Test::flatten_result_lists({
      CHECK_all("sessions expire",
                [&](auto, auto factory, auto& result) {
                   auto mgr = factory();

                   auto handle = mgr->establish(default_session(Botan::TLS::Connection_Side::Server, cbs));
                   result.require("saved successfully", handle.has_value());
                   result.require("session was found", mgr->retrieve(handle.value(), cbs, plcy).has_value());
                   cbs.tick();
                   result.confirm("session has expired", !mgr->retrieve(handle.value(), cbs, plcy).has_value());
                   result.test_is_eq("session was deleted when it expired", mgr->remove_all(), size_t(0));
                }),

         CHECK_all("expired sessions are not found",
                   [&](const std::string& type, auto factory, auto& result) {
                      if(type == "Stateless") {
                         return;  // this manager can neither store nor find anything
                      }

                      auto mgr = factory();

                      auto handle_old = random_id(*rng);
                      mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs), handle_old);
                      result.require("session was found", mgr->retrieve(handle_old, cbs, plcy).has_value());

                      cbs.tick();
                      auto handle_new = random_id(*rng);
                      mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs), handle_new);
                      result.require("session was found", mgr->retrieve(handle_new, cbs, plcy).has_value());

                      auto sessions_and_handles = mgr->find(server_info, cbs, plcy);
                      result.require("sessions are found", !sessions_and_handles.empty());
                      result.test_is_eq("exactly one session is found", sessions_and_handles.size(), size_t(1));
                      result.test_is_eq(
                         "the new session is found", sessions_and_handles.front().handle.id().value(), handle_new);

                      result.test_is_eq("old session was deleted when it expired", mgr->remove_all(), size_t(1));
                   }),

         CHECK_all(
            "session tickets are not reused",
            [&](const std::string& type, auto factory, auto& result) {
               if(type == "Stateless") {
                  return;  // this manager can neither store nor find anything
               }

               auto mgr = factory();

               auto handle_1 = random_id(*rng);
               mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs, Botan::TLS::Version_Code::TLS_V12),
                          handle_1);
               auto handle_2 = random_ticket(*rng);
               mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs, Botan::TLS::Version_Code::TLS_V12),
                          handle_2);

   #if defined(BOTAN_HAS_TLS_13)
               auto handle_3 = random_id(*rng);
               mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs, Botan::TLS::Version_Code::TLS_V13),
                          handle_3);
               auto handle_4 = random_ticket(*rng);
               mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs, Botan::TLS::Version_Code::TLS_V13),
                          handle_4);
   #endif

               plcy.set_allow_session_reuse(false);

               auto sessions_and_handles1 = mgr->find(server_info, cbs, plcy);
               result.require("all sessions are found", sessions_and_handles1.size() > 1);

               auto sessions_and_handles2 = mgr->find(server_info, cbs, plcy);
               result.test_is_eq("only one session is found", sessions_and_handles2.size(), size_t(1));
               result.confirm("found session is the Session_ID", sessions_and_handles2.front().handle.is_id());
               result.test_is_eq(
                  "found session is the Session_ID", sessions_and_handles2.front().handle.id().value(), handle_1);
               result.confirm("found session is TLS 1.2",
                              sessions_and_handles2.front().session.version().is_pre_tls_13());
            }),

         CHECK_all("number of found tickets is capped",
                   [&](const std::string& type, auto factory, auto& result) {
                      if(type == "Stateless") {
                         return;  // this manager can neither store nor find anything
                      }

                      auto mgr = factory();

                      std::array<Botan::TLS::Session_Ticket, 5> tickets;
                      for(auto& ticket : tickets) {
                         ticket = random_ticket(*rng);
                         mgr->store(default_session(Botan::TLS::Connection_Side::Client, cbs), ticket);
                      }

                      plcy.set_allow_session_reuse(true);

                      plcy.set_session_limit(1);
                      result.test_is_eq("find one",
                                        mgr->find(server_info, cbs, plcy).size(),
                                        plcy.maximum_session_tickets_per_client_hello());

                      plcy.set_session_limit(3);
                      result.test_is_eq("find three",
                                        mgr->find(server_info, cbs, plcy).size(),
                                        plcy.maximum_session_tickets_per_client_hello());

                      plcy.set_session_limit(10);
                      result.test_is_eq("find all five", mgr->find(server_info, cbs, plcy).size(), size_t(5));
                   }),

   #if defined(BOTAN_HAS_TLS_13)
         CHECK_all("expired tickets are not selected for PSK resumption", [&](auto, auto factory, auto& result) {
            auto ticket = [&](const Botan::TLS::Session_Handle& handle) {
               return Botan::TLS::PskIdentity(handle.opaque_handle().get(), 0);
            };

            auto mgr = factory();

            auto old_handle = mgr->establish(
               default_session(Botan::TLS::Connection_Side::Server, cbs, Botan::TLS::Version_Code::TLS_V13));
            cbs.tick();
            auto new_handle = mgr->establish(
               default_session(Botan::TLS::Connection_Side::Server, cbs, Botan::TLS::Version_Code::TLS_V13));
            result.require("both sessions are stored", old_handle.has_value() && new_handle.has_value());

            auto session_and_index = mgr->choose_from_offered_tickets(
               std::vector{ticket(old_handle.value()), ticket(new_handle.value())}, "SHA-256", cbs, plcy);
            result.require("a ticket was chosen", session_and_index.has_value());
            result.test_is_eq("the new ticket was chosen", session_and_index->second, uint16_t(1));

            cbs.tick();

            auto nothing = mgr->choose_from_offered_tickets(
               std::vector{ticket(new_handle.value()), ticket(old_handle.value())}, "SHA-256", cbs, plcy);
            result.require("all tickets are expired", !nothing.has_value());
         }),
   #endif
   });
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls",
                       "tls_session_manager",
                       test_session_manager_in_memory,
                       test_session_manager_choose_ticket,
                       test_session_manager_stateless,
                       test_session_manager_hybrid,
                       test_session_manager_sqlite,
                       tls_session_manager_expiry);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_TLS
