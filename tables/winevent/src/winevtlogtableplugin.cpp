#include "winevtlogtableplugin.h"

#include <chrono>
#include <limits>
#include <mutex>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;

namespace zeek {

struct WinevtlogTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status WinevtlogTablePlugin::create(Ref &obj,
                                          IZeekConfiguration &configuration,
                                          IZeekLogger &logger) {

  try {
    obj.reset(new WinevtlogTablePlugin(configuration, logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

WinevtlogTablePlugin::~WinevtlogTablePlugin() {}

const std::string &WinevtlogTablePlugin::name() const {
  static const std::string kTableName{"winevtlog"};

  return kTableName;
}

const WinevtlogTablePlugin::Schema &WinevtlogTablePlugin::schema() const {

  static const Schema kTableSchema = {
      {"zeek_time", IVirtualTable::ColumnType::Integer},
      {"date_time", IVirtualTable::ColumnType::String},

      // System data
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
      {"data", IVirtualTable::ColumnType::String}
  };

  return kTableSchema;
}

Status WinevtlogTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status WinevtlogTablePlugin::processEvents(
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
                         "winevtlog_events: Dropping " +
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

WinevtlogTablePlugin::WinevtlogTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {
  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status WinevtlogTablePlugin::generateRow(Row &row,
                                               const WELEvent &event) {
  row = {};

  std::cout << "WEL event ID: " << event.event_id << "\n";

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

  return Status::success();
}
} // namespace zeek