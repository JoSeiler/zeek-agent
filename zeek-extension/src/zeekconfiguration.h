/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <osquery/status.h>

namespace zeek {
class ZeekConfiguration final {
 public:
  using Ref = std::unique_ptr<ZeekConfiguration>;
  static osquery::Status create(Ref& ref, const std::string& path);

  ~ZeekConfiguration();

  const std::string& serverAddress() const;
  std::uint16_t serverPort() const;
  const std::string& groupList() const;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ZeekConfiguration(const std::string& path);
};
} // namespace zeek