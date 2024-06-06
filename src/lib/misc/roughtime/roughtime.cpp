/*
* Roughtime
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/roughtime.h>

#include <botan/base64.h>
#include <botan/hash.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/internal/socket_udp.h>

#include <cmath>
#include <map>
#include <sstream>

namespace Botan {

namespace {

// This exists to work around a LGTM false positive
static_assert(Roughtime::request_min_size == 1024, "Expected minimum size");

template <class T>
struct is_array : std::false_type {};

template <class T, std::size_t N>
struct is_array<std::array<T, N>> : std::true_type {};

template <typename T>
T impl_from_little_endian(const uint8_t* t, const size_t i)
   requires(sizeof(T) <= sizeof(int64_t))
{
   return T(static_cast<int64_t>(t[i]) << i * 8) + (i == 0 ? T(0) : impl_from_little_endian<T>(t, i - 1));
}

template <typename T>
T from_little_endian(const uint8_t* t) {
   return impl_from_little_endian<T>(t, sizeof(T) - 1);
}

template <typename T>
T copy(const uint8_t* t)
   requires(is_array<T>::value)
{
   return typecast_copy<T>(t);  //arrays are endianess independent, so we do a memcpy
}

template <typename T>
T copy(const uint8_t* t)
   requires(!is_array<T>::value)
{
   //other types are arithmetic, so we account that roughtime serializes as little endian
   return from_little_endian<T>(t);
}

template <typename T>
std::map<std::string, std::vector<uint8_t>> unpack_roughtime_packet(T bytes) {
   if(bytes.size() < 8) {
      throw Roughtime::Roughtime_Error("Map length is under minimum of 8 bytes");
   }
   const auto buf = bytes.data();
   const uint32_t num_tags = buf[0];
   const uint32_t start_content = num_tags * 8;
   if(start_content > bytes.size()) {
      throw Roughtime::Roughtime_Error("Map length too small to contain all tags");
   }
   uint32_t start = start_content;
   std::map<std::string, std::vector<uint8_t>> tags;
   for(uint32_t i = 0; i < num_tags; ++i) {
      const size_t end =
         ((i + 1) == num_tags) ? bytes.size() : start_content + from_little_endian<uint32_t>(buf + 4 + i * 4);
      if(end > bytes.size()) {
         throw Roughtime::Roughtime_Error("Tag end index out of bounds");
      }
      if(end < start) {
         throw Roughtime::Roughtime_Error("Tag offset must be more than previous tag offset");
      }
      const char* label_ptr = cast_uint8_ptr_to_char(buf) + (num_tags + i) * 4;
      const char label[] = {label_ptr[0], label_ptr[1], label_ptr[2], label_ptr[3], 0};
      auto ret = tags.emplace(label, std::vector<uint8_t>(buf + start, buf + end));
      if(!ret.second) {
         throw Roughtime::Roughtime_Error(std::string("Map has duplicated tag: ") + label);
      }
      start = static_cast<uint32_t>(end);
   }
   return tags;
}

template <typename T>
T get(const std::map<std::string, std::vector<uint8_t>>& map, const std::string& label) {
   const auto& tag = map.find(label);
   if(tag == map.end()) {
      throw Roughtime::Roughtime_Error("Tag " + label + " not found");
   }
   if(tag->second.size() != sizeof(T)) {
      throw Roughtime::Roughtime_Error("Tag " + label + " has unexpected size");
   }
   return copy<T>(tag->second.data());
}

const std::vector<uint8_t>& get_v(const std::map<std::string, std::vector<uint8_t>>& map, const std::string& label) {
   const auto& tag = map.find(label);
   if(tag == map.end()) {
      throw Roughtime::Roughtime_Error("Tag " + label + " not found");
   }
   return tag->second;
}

bool verify_signature(const std::array<uint8_t, 32>& pk,
                      const std::vector<uint8_t>& payload,
                      const std::array<uint8_t, 64>& signature) {
   const char context[] = "RoughTime v1 response signature";
   Ed25519_PublicKey key(std::vector<uint8_t>(pk.data(), pk.data() + pk.size()));
   PK_Verifier verifier(key, "Pure");
   verifier.update(cast_char_ptr_to_uint8(context), sizeof(context));  //add context including \0
   verifier.update(payload);
   return verifier.check_signature(signature.data(), signature.size());
}

std::array<uint8_t, 64> hashLeaf(const std::array<uint8_t, 64>& leaf) {
   std::array<uint8_t, 64> ret{};
   auto hash = HashFunction::create_or_throw("SHA-512");
   hash->update(0);
   hash->update(leaf.data(), leaf.size());
   hash->final(ret.data());
   return ret;
}

void hashNode(std::array<uint8_t, 64>& hash, const std::array<uint8_t, 64>& node, bool reverse) {
   auto h = HashFunction::create_or_throw("SHA-512");
   h->update(1);
   if(reverse) {
      h->update(node.data(), node.size());
      h->update(hash.data(), hash.size());
   } else {
      h->update(hash.data(), hash.size());
      h->update(node.data(), node.size());
   }
   h->final(hash.data());
}

template <size_t N, typename T>
std::array<uint8_t, N> vector_to_array(std::vector<uint8_t, T> vec) {
   if(vec.size() != N) {
      throw std::logic_error("Invalid vector size");
   }
   return typecast_copy<std::array<uint8_t, N>>(vec.data());
}
}  // namespace

namespace Roughtime {

Nonce::Nonce(const std::vector<uint8_t>& nonce) {
   if(nonce.size() != 64) {
      throw Invalid_Argument("Roughtime nonce must be 64 bytes long");
   }
   m_nonce = typecast_copy<std::array<uint8_t, 64>>(nonce.data());
}

Nonce::Nonce(RandomNumberGenerator& rng) {
   rng.randomize(m_nonce.data(), m_nonce.size());
}

std::array<uint8_t, request_min_size> encode_request(const Nonce& nonce) {
   std::array<uint8_t, request_min_size> buf = {{2, 0, 0, 0, 64, 0, 0, 0, 'N', 'O', 'N', 'C', 'P', 'A', 'D', 0xff}};
   std::memcpy(buf.data() + 16, nonce.get_nonce().data(), nonce.get_nonce().size());
   std::memset(buf.data() + 16 + nonce.get_nonce().size(), 0, buf.size() - 16 - nonce.get_nonce().size());
   return buf;
}

Response Response::from_bits(const std::vector<uint8_t>& response, const Nonce& nonce) {
   const auto response_v = unpack_roughtime_packet(response);
   const auto cert = unpack_roughtime_packet(get_v(response_v, "CERT"));
   const auto cert_dele = get<std::array<uint8_t, 72>>(cert, "DELE");
   const auto cert_sig = get<std::array<uint8_t, 64>>(cert, "SIG");
   const auto cert_dele_v = unpack_roughtime_packet(cert_dele);
   const auto srep = get_v(response_v, "SREP");
   const auto srep_v = unpack_roughtime_packet(srep);

   const auto cert_dele_pubk = get<std::array<uint8_t, 32>>(cert_dele_v, "PUBK");
   const auto sig = get<std::array<uint8_t, 64>>(response_v, "SIG");
   if(!verify_signature(cert_dele_pubk, srep, sig)) {
      throw Roughtime_Error("Response signature invalid");
   }

   const auto indx = get<uint32_t>(response_v, "INDX");
   const auto path = get_v(response_v, "PATH");
   const auto srep_root = get<std::array<uint8_t, 64>>(srep_v, "ROOT");
   const size_t size = path.size();
   const size_t levels = size / 64;

   if(size % 64) {
      throw Roughtime_Error("Merkle tree path size must be multiple of 64 bytes");
   }
   if(indx >= (1U << levels)) {
      throw Roughtime_Error("Merkle tree path is too short");
   }

   auto hash = hashLeaf(nonce.get_nonce());
   auto index = indx;
   size_t level = 0;
   while(level < levels) {
      hashNode(hash, typecast_copy<std::array<uint8_t, 64>>(path.data() + level * 64), index & 1);
      ++level;
      index >>= 1;
   }

   if(srep_root != hash) {
      throw Roughtime_Error("Nonce verification failed");
   }

   const auto cert_dele_maxt = sys_microseconds64(get<microseconds64>(cert_dele_v, "MAXT"));
   const auto cert_dele_mint = sys_microseconds64(get<microseconds64>(cert_dele_v, "MINT"));
   const auto srep_midp = sys_microseconds64(get<microseconds64>(srep_v, "MIDP"));
   const auto srep_radi = get<microseconds32>(srep_v, "RADI");
   if(srep_midp < cert_dele_mint) {
      throw Roughtime_Error("Midpoint earlier than delegation start");
   }
   if(srep_midp > cert_dele_maxt) {
      throw Roughtime_Error("Midpoint later than delegation end");
   }
   return {cert_dele, cert_sig, srep_midp, srep_radi};
}

bool Response::validate(const Ed25519_PublicKey& pk) const {
   const char context[] = "RoughTime v1 delegation signature--";
   PK_Verifier verifier(pk, "Pure");
   verifier.update(cast_char_ptr_to_uint8(context), sizeof(context));  //add context including \0
   verifier.update(m_cert_dele.data(), m_cert_dele.size());
   return verifier.check_signature(m_cert_sig.data(), m_cert_sig.size());
}

Nonce nonce_from_blind(const std::vector<uint8_t>& previous_response, const Nonce& blind) {
   std::array<uint8_t, 64> ret{};
   const auto blind_arr = blind.get_nonce();
   auto hash = HashFunction::create_or_throw("SHA-512");
   hash->update(previous_response);
   hash->update(hash->final());
   hash->update(blind_arr.data(), blind_arr.size());
   hash->final(ret.data());

   return ret;
}

Chain::Chain(std::string_view str) {
   std::istringstream ss{std::string(str)};  // FIXME C++23 avoid copy
   const std::string ERROR_MESSAGE = "Line does not have 4 space separated fields";
   for(std::string s; std::getline(ss, s);) {
      size_t start = 0, end = 0;
      end = s.find(' ', start);
      if(end == std::string::npos) {
         throw Decoding_Error(ERROR_MESSAGE);
      }
      const auto publicKeyType = s.substr(start, end - start);
      if(publicKeyType != "ed25519") {
         throw Not_Implemented("Only ed25519 publicKeyType is implemented");
      }

      start = end + 1;
      end = s.find(' ', start);
      if(end == std::string::npos) {
         throw Decoding_Error(ERROR_MESSAGE);
      }
      const auto serverPublicKey = Ed25519_PublicKey(base64_decode(s.substr(start, end - start)));

      start = end + 1;
      end = s.find(' ', start);
      if(end == std::string::npos) {
         throw Decoding_Error(ERROR_MESSAGE);
      }
      if((end - start) != 88) {
         throw Decoding_Error("Nonce has invalid length");
      }
      const auto vec = base64_decode(s.substr(start, end - start));
      const auto nonceOrBlind = Nonce(vector_to_array<64>(base64_decode(s.substr(start, end - start))));

      start = end + 1;
      end = s.find(' ', start);
      if(end != std::string::npos) {
         throw Decoding_Error(ERROR_MESSAGE);
      }
      const auto response = unlock(base64_decode(s.substr(start)));

      m_links.push_back({response, serverPublicKey, nonceOrBlind});
   }
}

std::vector<Response> Chain::responses() const {
   std::vector<Response> responses;
   for(unsigned i = 0; i < m_links.size(); ++i) {
      const auto& l = m_links[i];
      const auto nonce = i ? nonce_from_blind(m_links[i - 1].response(), l.nonce_or_blind()) : l.nonce_or_blind();
      const auto response = Response::from_bits(l.response(), nonce);
      if(!response.validate(l.public_key())) {
         throw Roughtime_Error("Invalid signature or public key");
      }
      responses.push_back(response);
   }
   return responses;
}

Nonce Chain::next_nonce(const Nonce& blind) const {
   return m_links.empty() ? blind : nonce_from_blind(m_links.back().response(), blind);
}

void Chain::append(const Link& new_link, size_t max_chain_size) {
   if(max_chain_size <= 0) {
      throw Invalid_Argument("Max chain size must be positive");
   }

   while(m_links.size() >= max_chain_size) {
      if(m_links.size() == 1) {
         auto new_link_updated = new_link;
         new_link_updated.nonce_or_blind() =
            nonce_from_blind(m_links[0].response(), new_link.nonce_or_blind());  //we need to convert blind to nonce
         m_links.clear();
         m_links.push_back(new_link_updated);
         return;
      }
      if(m_links.size() >= 2) {
         m_links[1].nonce_or_blind() =
            nonce_from_blind(m_links[0].response(), m_links[1].nonce_or_blind());  //we need to convert blind to nonce
      }
      m_links.erase(m_links.begin());
   }
   m_links.push_back(new_link);
}

std::string Chain::to_string() const {
   std::string s;
   s.reserve((7 + 1 + 88 + 1 + 44 + 1 + 480) * m_links.size());
   for(const auto& link : m_links) {
      s += "ed25519";
      s += ' ';
      s += base64_encode(link.public_key().get_public_key());
      s += ' ';
      s += base64_encode(link.nonce_or_blind().get_nonce().data(), link.nonce_or_blind().get_nonce().size());
      s += ' ';
      s += base64_encode(link.response());
      s += '\n';
   }
   return s;
}

std::vector<uint8_t> online_request(std::string_view uri, const Nonce& nonce, std::chrono::milliseconds timeout) {
   const std::chrono::system_clock::time_point start_time = std::chrono::system_clock::now();
   auto socket = OS::open_socket_udp(uri, timeout);
   if(!socket) {
      throw Not_Implemented("No socket support enabled in build");
   }

   const auto encoded = encode_request(nonce);
   socket->write(encoded.data(), encoded.size());

   if(std::chrono::system_clock::now() - start_time > timeout) {
      throw System_Error("Timeout during socket write");
   }

   std::vector<uint8_t> buffer;
   buffer.resize(360 + 64 * 10 + 1);  //response basic size is 360 bytes + 64 bytes for each level of merkle tree
                                      //add one additional byte to be able to differentiate if datagram got truncated
   const auto n = socket->read(buffer.data(), buffer.size());

   if(!n || std::chrono::system_clock::now() - start_time > timeout) {
      throw System_Error("Timeout waiting for response");
   }

   if(n == buffer.size()) {
      throw System_Error("Buffer too small");
   }

   buffer.resize(n);
   return buffer;
}

std::vector<Server_Information> servers_from_str(std::string_view str) {
   std::vector<Server_Information> servers;
   std::istringstream ss{std::string(str)};  // FIXME C++23 avoid copy

   const std::string ERROR_MESSAGE = "Line does not have at least 5 space separated fields";
   for(std::string s; std::getline(ss, s);) {
      size_t start = 0, end = 0;
      end = s.find(' ', start);
      if(end == std::string::npos) {
         throw Decoding_Error(ERROR_MESSAGE);
      }
      const auto name = s.substr(start, end - start);

      start = end + 1;
      end = s.find(' ', start);
      if(end == std::string::npos) {
         throw Decoding_Error(ERROR_MESSAGE);
      }
      const auto publicKeyType = s.substr(start, end - start);
      if(publicKeyType != "ed25519") {
         throw Not_Implemented("Only ed25519 publicKeyType is implemented");
      }

      start = end + 1;
      end = s.find(' ', start);

      if(end == std::string::npos) {
         throw Decoding_Error(ERROR_MESSAGE);
      }
      const auto publicKeyBase64 = s.substr(start, end - start);
      const auto publicKey = Ed25519_PublicKey(base64_decode(publicKeyBase64));

      start = end + 1;
      end = s.find(' ', start);
      if(end == std::string::npos) {
         throw Decoding_Error(ERROR_MESSAGE);
      }
      const auto protocol = s.substr(start, end - start);
      if(protocol != "udp") {
         throw Not_Implemented("Only UDP protocol is implemented");
      }

      const auto addresses = [&]() {
         std::vector<std::string> addr;
         for(;;) {
            start = end + 1;
            end = s.find(' ', start);
            const auto address = s.substr(start, (end == std::string::npos) ? std::string::npos : end - start);
            if(address.empty()) {
               return addr;
            }
            addr.push_back(address);
            if(end == std::string::npos) {
               return addr;
            }
         }
      }();
      if(addresses.empty()) {
         throw Decoding_Error(ERROR_MESSAGE);
      }

      servers.push_back({name, publicKey, addresses});
   }
   return servers;
}

}  // namespace Roughtime

}  // namespace Botan
