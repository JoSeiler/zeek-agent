#pragma once

#include <ctime>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <zeek/iwineventconsumer.h>
#include <zeek/status.h>

namespace zeek {

// Process event log and generate the property_tree object
Status parseWindowsEventLogXML(boost::property_tree::ptree& event_object,
                               const std::wstring& xml_event);

// Utility function to parse the windows event property tree
Status parseWindowsEventLogPTree(
    WELEvent& windows_event, const boost::property_tree::ptree& event_object);


} // namespace zeek