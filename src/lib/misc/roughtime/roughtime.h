/*
* Roughtime
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ROUGHTIME_H_
#define BOTAN_ROUGHTIME_H_

#include <array>
#include <chrono>
#include <vector>

#include <botan/ed25519.h>

namespace Botan {

class RandomNumberGenerator;

namespace Roughtime {

/**
* The fixed size of a Roughtime request
*/
const unsigned request_min_size = 1024;

/**
* An error occurred while processing a Roughtime message
*/
class BOTAN_PUBLIC_API(2, 13) Roughtime_Error final : public Decoding_Error {
   public:
      /**
      * Create a Roughtime_Error
      * @param s a description of the failure
      */
      explicit Roughtime_Error(std::string_view s) : Decoding_Error("Roughtime", s) {}

      /**
      * Return the error type of this exception
      * @return always ErrorType::RoughtimeError
      */
      ErrorType error_type() const noexcept override { return ErrorType::RoughtimeError; }
};

/**
* A 64 byte Roughtime nonce
*/
class BOTAN_PUBLIC_API(2, 13) Nonce final {
   public:
      /**
      * Create an uninitialized nonce
      */
      Nonce() = default;

      /**
      * Create a nonce from a 64 byte vector
      * @param nonce the nonce bytes
      */
      explicit Nonce(const std::vector<uint8_t>& nonce);

      /**
      * Create a random nonce
      * @param rng a random number generator
      */
      explicit Nonce(RandomNumberGenerator& rng);

      /**
      * Create a nonce from a 64 byte array
      * @param nonce the nonce bytes
      */
      explicit Nonce(const std::array<uint8_t, 64>& nonce) : m_nonce(nonce) {}

      /**
      * Compare two nonces
      * @param rhs the nonce to compare against
      * @return true if the nonces are equal
      */
      bool operator==(const Nonce& rhs) const { return m_nonce == rhs.m_nonce; }

      /**
      * Access the nonce bytes
      * @return the 64 nonce bytes
      */
      const std::array<uint8_t, 64>& get_nonce() const { return m_nonce; }

   private:
      std::array<uint8_t, 64> m_nonce;
};

/**
* An Roughtime request.
*
* @param nonce the nonce to include in the request
* @return the encoded request
*/
BOTAN_PUBLIC_API(2, 13)
std::array<uint8_t, request_min_size> encode_request(const Nonce& nonce);

/**
* An Roughtime response.
*/
class BOTAN_PUBLIC_API(2, 13) Response final {
   public:
      /**
      * A 32 bit microsecond duration
      */
      using microseconds32 = std::chrono::duration<uint32_t, std::micro>;

      /**
      * A 64 bit microsecond duration
      */
      using microseconds64 = std::chrono::duration<uint64_t, std::micro>;

      /**
      * A system clock time point with microsecond resolution
      */
      using sys_microseconds64 = std::chrono::time_point<std::chrono::system_clock, microseconds64>;

      /**
      * Parse a Roughtime response
      * @param response the raw response bytes
      * @param nonce the nonce which was sent in the request
      * @return the parsed response
      */
      static Response from_bits(const std::vector<uint8_t>& response, const Nonce& nonce);

      /**
      * Check the signatures on this response
      * @param pk the long term public key of the server
      * @return true if the response is valid
      */
      bool validate(const Ed25519_PublicKey& pk) const;

      /**
      * Return the midpoint of the time interval reported by the server
      * @return the UTC midpoint
      */
      sys_microseconds64 utc_midpoint() const { return m_utc_midpoint; }

      /**
      * Return the radius of the time interval reported by the server
      * @return the UTC radius
      */
      microseconds32 utc_radius() const { return m_utc_radius; }

   private:
      Response(const std::array<uint8_t, 72>& dele,
               const std::array<uint8_t, 64>& sig,
               sys_microseconds64 utc_midp,
               microseconds32 utc_radius) :
            m_cert_dele(dele), m_cert_sig(sig), m_utc_midpoint{utc_midp}, m_utc_radius{utc_radius} {}

      const std::array<uint8_t, 72> m_cert_dele;
      const std::array<uint8_t, 64> m_cert_sig;
      const sys_microseconds64 m_utc_midpoint;
      const microseconds32 m_utc_radius;
};

/**
* One response in a Roughtime chain
*/
class BOTAN_PUBLIC_API(2, 13) Link final {
   public:
      /**
      * Create a chain link
      * @param response the raw response bytes
      * @param public_key the public key of the server which produced it
      * @param nonce_or_blind the nonce, or for later links the blind
      */
      Link(const std::vector<uint8_t>& response, const Ed25519_PublicKey& public_key, const Nonce& nonce_or_blind) :
            m_response{response}, m_public_key{public_key}, m_nonce_or_blind{nonce_or_blind} {}

      /**
      * Access the raw response
      * @return the raw response bytes
      */
      const std::vector<uint8_t>& response() const { return m_response; }

      /**
      * Access the server public key
      * @return the public key of the server
      */
      const Ed25519_PublicKey& public_key() const { return m_public_key; }

      /**
      * Access the nonce or blind
      * @return the nonce, or for later links the blind
      */
      const Nonce& nonce_or_blind() const { return m_nonce_or_blind; }

      /**
      * Access the nonce or blind
      * @return the nonce, or for later links the blind
      */
      Nonce& nonce_or_blind() { return m_nonce_or_blind; }

   private:
      std::vector<uint8_t> m_response;
      Ed25519_PublicKey m_public_key;
      Nonce m_nonce_or_blind;
};

/**
* A chain of Roughtime responses
*/
class BOTAN_PUBLIC_API(2, 13) Chain final {
   public:
      /**
      * Create an empty chain
      */
      Chain() = default;  //empty

      /**
      * Parse a chain from its string representation
      * @param str the chain to parse
      */
      explicit Chain(std::string_view str);

      /**
      * Access the links of this chain
      * @return the links
      */
      const std::vector<Link>& links() const { return m_links; }

      /**
      * Parse and validate every response in the chain
      * @return the parsed responses
      */
      std::vector<Response> responses() const;

      /**
      * Compute the nonce to use for the next request
      * @param blind the blind to use
      * @return the next nonce
      */
      Nonce next_nonce(const Nonce& blind) const;

      /**
      * Append a link, dropping the oldest links if needed
      * @param new_link the link to append
      * @param max_chain_size the maximum number of links to retain
      */
      void append(const Link& new_link, size_t max_chain_size);

      /**
      * Format this chain as a string
      * @return the string representation of the chain
      */
      std::string to_string() const;

   private:
      std::vector<Link> m_links;
};

/**
* Derive a nonce from the previous response and a blind
* @param previous_response the raw bytes of the previous response
* @param blind the blind to use
* @return the derived nonce
*/
BOTAN_PUBLIC_API(2, 13)
Nonce nonce_from_blind(const std::vector<uint8_t>& previous_response, const Nonce& blind);

/**
* Makes an online Roughtime request via UDP and returns the Roughtime response.
* @param url Roughtime server UDP endpoint (host:port)
* @param nonce the nonce to send to the server
* @param timeout a timeout on the UDP request
* @return Roughtime response
*/
BOTAN_PUBLIC_API(2, 13)
std::vector<uint8_t> online_request(std::string_view url,
                                    const Nonce& nonce,
                                    std::chrono::milliseconds timeout = std::chrono::seconds(3));

/**
* The name, key and addresses of a Roughtime server
*/
struct BOTAN_PUBLIC_API(2, 13) Server_Information final {
   public:
      /**
      * Create a server description
      * @param name the name of the server
      * @param public_key the long term public key of the server
      * @param addresses the endpoints of the server
      */
      Server_Information(std::string_view name,
                         const Ed25519_PublicKey& public_key,
                         const std::vector<std::string>& addresses) :
            m_name{name}, m_public_key{public_key}, m_addresses{addresses} {}

      /**
      * Access the server name
      * @return the name of the server
      */
      const std::string& name() const { return m_name; }

      /**
      * Access the server public key
      * @return the long term public key of the server
      */
      const Ed25519_PublicKey& public_key() const { return m_public_key; }

      /**
      * Access the server addresses
      * @return the endpoints of the server
      */
      const std::vector<std::string>& addresses() const { return m_addresses; }

   private:
      std::string m_name;
      Ed25519_PublicKey m_public_key;
      std::vector<std::string> m_addresses;
};

/**
* Parse a list of server descriptions
* @param str the server list to parse
* @return the parsed servers
*/
BOTAN_PUBLIC_API(2, 13)
std::vector<Server_Information> servers_from_str(std::string_view str);

}  // namespace Roughtime
}  // namespace Botan

#endif
