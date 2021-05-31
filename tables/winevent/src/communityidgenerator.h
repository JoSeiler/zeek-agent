#pragma once

#include <zeek/status.h>

namespace zeek {

/// The buffer used to maintain the context and state of the hashing
/// operations
extern void* ctx_;

/// The length of the hash to be returned
extern size_t length_;

const extern std::string v1;

const extern int supported_protocols[];

bool checkProtocol(const int64_t proto);

std::string communityIDv1(const std::string saddr_str, const std::string daddr_str,
                          int64_t sport, int64_t dport, const int64_t proto);

void update(const void* buffer, size_t size);

std::string digest();

std::string encode(const std::string &unencoded);

} // namespace zeek