#include "networkconntableplugin.h"
#include "communityidgenerator.h"

#include <chrono>
#include <limits>
#include <mutex>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;

namespace zeek {

struct NetworkConnTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status NetworkConnTablePlugin::create(Ref &obj,
                                       IZeekConfiguration &configuration,
                                       IZeekLogger &logger) {

  try {
    obj.reset(new NetworkConnTablePlugin(configuration, logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

NetworkConnTablePlugin::~NetworkConnTablePlugin() {}

const std::string &NetworkConnTablePlugin::name() const {
  static const std::string kTableName{"network_conn"};

  return kTableName;
}

const NetworkConnTablePlugin::Schema &NetworkConnTablePlugin::schema() const {

  static const Schema kTableSchema = {
      // System data
      {"zeek_time", IVirtualTable::ColumnType::Integer},
      {"date_time", IVirtualTable::ColumnType::String},

      {"source", IVirtualTable::ColumnType::String},
      {"provider_name", IVirtualTable::ColumnType::String},
      {"provider_guid", IVirtualTable::ColumnType::String},
      {"computer_name", IVirtualTable::ColumnType::String},

      {"event_id", IVirtualTable::ColumnType::Integer},
      {"task_id", IVirtualTable::ColumnType::Integer},
      {"level", IVirtualTable::ColumnType::Integer},
      {"pid", IVirtualTable::ColumnType::Integer},
      {"tid", IVirtualTable::ColumnType::Integer},

      {"keywords", IVirtualTable::ColumnType::String},
      {"data", IVirtualTable::ColumnType::String},

      // Event data
      {"process_id", IVirtualTable::ColumnType::Integer},
      {"application", IVirtualTable::ColumnType::String},
      {"direction", IVirtualTable::ColumnType::String},
      {"source_address", IVirtualTable::ColumnType::String},
      {"source_port", IVirtualTable::ColumnType::Integer},
      {"dest_address", IVirtualTable::ColumnType::String},
      {"dest_port", IVirtualTable::ColumnType::Integer},
      {"protocol", IVirtualTable::ColumnType::Integer},
      {"filter_rtid", IVirtualTable::ColumnType::Integer},
      {"layer_name", IVirtualTable::ColumnType::String},
      {"layer_rtid", IVirtualTable::ColumnType::Integer},
      {"remote_user_id", IVirtualTable::ColumnType::String},
      {"remote_machine_id", IVirtualTable::ColumnType::String}
  };

  return kTableSchema;
}

Status NetworkConnTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status NetworkConnTablePlugin::processEvents(
    const IWinevtlogConsumer::EventList &event_list) {

  for (const auto &event : event_list) {
    Row row;

    auto status = generateRow(row, event);
    if (!status.succeeded()) {
      return status;
    }

    if (!row.empty()) {
      {
        std::lock_guard<std::mutex> lock(d->row_list_mutex);
        d->row_list.push_back(row);
      }
    }
  }

  if (d->row_list.size() > d->max_queued_row_count) {

    auto rows_to_remove = d->row_list.size() - d->max_queued_row_count;

    d->logger.logMessage(IZeekLogger::Severity::Warning,
                         "network_conn_events: Dropping " +
                         std::to_string(rows_to_remove) +
                         " rows (max row count is set to " +
                         std::to_string(d->max_queued_row_count) + ")");

    {
      std::lock_guard<std::mutex> lock(d->row_list_mutex);
      d->row_list.erase(d->row_list.begin(),
                        std::next(d->row_list.begin(), rows_to_remove));
    }
  }

  return Status::success();
}

NetworkConnTablePlugin::NetworkConnTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {
  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status NetworkConnTablePlugin::generateRow(Row &row,
                                     const WELEvent &event) {
  row = {};

  if (event.event_id != 5156) {
    return Status::success();
  }

  std::cout << "Network conn event: id: " << event.event_id << "\n";

  row["zeek_time"] = event.zeek_time;
  row["date_time"] = event.datetime;

  row["source"] = event.source;
  row["provider_name"] = event.provider_name;
  row["provider_guid"] = event.provider_guid;
  row["computer_name"] = event.computer_name;

  row["event_id"] = event.event_id;
  row["task_id"] = event.task_id;
  row["level"] = event.level;
  row["pid"] = event.pid;
  row["tid"] = event.tid;

  row["keywords"] = event.keywords;
  row["data"] = event.data;

  pt::ptree strTree;
  std::stringstream stream(event.data);

  try {
    pt::read_json(stream, strTree);
  }
  catch (pt::ptree_error & e) {
    return Status::failure("Error: event data is illformed" + *e.what());
  }

  row["process_id"] = static_cast<std::int64_t>(strTree.get("EventData.Protocol", -1));
  row["application"] = strTree.get("EventData.Application", "");
  row["direction"] = strTree.get("EventData.Direction", "");
  row["source_address"] = strTree.get("EventData.SourceAddress", "");
  row["source_port"] = static_cast<std::int64_t>(strTree.get("EventData.SourcePort", -1));
  row["dest_address"] = strTree.get("EventData.DestAddress", "");
  row["dest_port"] = static_cast<std::int64_t>(strTree.get("EventData.DestPort", -1));
  row["protocol"] = static_cast<std::int64_t>(strTree.get("EventData.Protocol", -1));
  row["filter_rtid"] = static_cast<std::int64_t>(strTree.get("EventData.FilterRTID", -1));
  row["layer_name"] = strTree.get("EventData.LayerName", "");
  row["layer_rtid"] = static_cast<std::int64_t>(strTree.get("EventData.LayerRTID", -1));
  row["remote_user_id"] = strTree.get("EventData.RemoteUserID", "");
  row["remote_machine_id"] = strTree.get("EventData.RemoteMachineID", "");

  //std::string proto = strTree.get("EventData.Protocol", "");

  //if ( checkProtocol( proto ) {
  //  std::cout << "supported";
  //}

  std::cout << "Here's event.data in network_conn table: " << event.data << "\n";
  std::cout << "eventdata protocol: " << strTree.get("EventData.Protocol", "") << "\n";
  std::cout << "eventdata source_address: " << strTree.get("EventData.SourceAddress", "") << "\n";

  return Status::success();

}
} // namespace zeek