#pragma once

#include <ctime>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <zeek/status.h>

namespace zeek {

struct WELEvent final {
  std::time_t osquery_time{0U};
  std::string datetime;

  std::string source;
  std::string provider_name;
  std::string provider_guid;
  std::string computer_name;

  std::int64_t event_id{0U};
  std::int64_t task_id{0U};
  std::int64_t level{0U};
  std::int64_t pid{0U};
  std::int64_t tid{0U};

  std::string keywords;
  std::string data;
};

// Process event log and generate the property_tree object
Status parseWindowsEventLogXML(boost::property_tree::ptree& event_object,
                               const std::wstring& xml_event);

// Utility function to parse the windows event property tree
Status parseWindowsEventLogPTree(
    WELEvent& windows_event, const boost::property_tree::ptree& event_object);

} // namespace zeek