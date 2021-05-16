#pragma once

#include <zeek/status.h>

namespace zeek {

  int commID_proto[] = {
    1,  // ICMP
    6,  // TCP
    17, // UDP
    46, // RSVP
    58, // ICMP6
    132 // SCTP
};

  bool checkProtocol(std::string proto);

} // namespace zeek