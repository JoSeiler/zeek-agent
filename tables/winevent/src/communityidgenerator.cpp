
#pragma warning( disable : 4127 ) // todo is there a solution to fix this issue?

#include "communityidgenerator.h"

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <boost/asio/ip/address.hpp>
#include <boost/endian/buffers.hpp>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace bai = boost::archive::iterators;
namespace errc = boost::system::errc;
namespace ip = boost::asio::ip;

namespace zeek {

typedef bai::binary_from_base64<const char*> base64_str;
typedef bai::transform_width<base64_str, 8, 6> base64_dec;
typedef bai::transform_width<std::string::const_iterator, 6, 8> base64_enc;
typedef bai::base64_from_binary<base64_enc> it_base64;

size_t length_ = SHA_DIGEST_LENGTH;
void* ctx_ = static_cast<SHA_CTX*>(malloc(sizeof(SHA_CTX)));

const std::string v1 = "1:";

const int supported_protocols[6] = {
    1,  // ICMP
    6,  // TCP
    17, // UDP
    46, // RSVP
    58, // ICMP6
    132 // SCTP
};

bool checkProtocol(const int64_t proto) {
  bool supported = std::find(std::begin(supported_protocols),
                             std::end(supported_protocols), proto) != std::end(supported_protocols);
  return supported;
}

std::string communityIDv1(const std::string saddr_str, const std::string daddr_str,
                          int64_t sport, int64_t dport, int64_t proto) {

  uint16_t seed = 0;

  boost::system::error_code ec;
  ip::address saddr = ip::make_address(saddr_str, ec);
  if (ec.value() != errc::success) {
    std::cout << "Community ID hash saddr cannot be parsed as IP" << "\n";
    return "";
  }
  ip::address daddr = ip::make_address(daddr_str, ec);
  if (ec.value() != errc::success) {
    std::cout << "Community ID hash daddr cannot be parsed as IP" << "\n";
    return "";
  }

  // Check source and destination ports
  if (sport < 0 || sport > UINT16_MAX || dport < 0 || dport > UINT16_MAX) {
    std::cout << "Community ID ports must fit in 2 bytes" << "\n";
    return "";
  }

  //Ensure ordering; if source address is larger switch order
  if (!(saddr < daddr || (saddr == daddr && sport < dport))) {
    std::swap(saddr, daddr);
    int64_t tmpPort = sport;
    sport = dport;
    dport = tmpPort;
  }

  std::stringstream bytes;
  bytes.write(reinterpret_cast<const char*>(&seed), 2);

  if (saddr.is_v4()) {
    bytes.write(reinterpret_cast<const char*>(saddr.to_v4().to_bytes().data()),
                4);
  } else {
    bytes.write(reinterpret_cast<const char*>(saddr.to_v6().to_bytes().data()),
                16);
  }
  if (daddr.is_v4()) {
    bytes.write(reinterpret_cast<const char*>(daddr.to_v4().to_bytes().data()),
                4);
  } else {
    bytes.write(reinterpret_cast<const char*>(daddr.to_v6().to_bytes().data()),
                16);
  }

  bytes.write(reinterpret_cast<const char*>(&proto), 1);
  bytes.put(0);
  bytes.put(0);
  bytes.write(reinterpret_cast<const char*>(&sport), 2);
  bytes.write(reinterpret_cast<const char*>(&dport), 2);

  std::string res = bytes.str();

  update(res.c_str(), res.size());
  auto result = v1 + digest();

  return result.c_str();
}

void update (const void* buffer, size_t size) {
  SHA1_Init(static_cast<SHA_CTX*>(ctx_));
  SHA1_Update(static_cast<SHA_CTX*>(ctx_), buffer, size);
}

std::string digest() {
  std::vector<unsigned char> hash;
  hash.assign(length_, '\0');

  SHA1_Final(hash.data(), static_cast<SHA_CTX*>(ctx_));

  std::stringstream digest;
  for (size_t i=0; i < length_; i++) {
    digest << hash[i];
  }

  return encode(digest.str());
}

std::string encode(const std::string &unencoded) {
  if (unencoded.empty()) {
    return unencoded;
  }

  size_t writePaddChars = (3U - unencoded.length() % 3U) % 3U;
  try {
    auto encoded =
        std::string(it_base64(unencoded.begin()), it_base64(unencoded.end()));
    encoded.append(std::string(writePaddChars, '='));
    return encoded;
  } catch (const boost::archive::iterators::dataflow_exception& e) {
    std::cout << "Could not base64 encode string: " << e.what();
    return "";
  }
}

} // namespace zeek
