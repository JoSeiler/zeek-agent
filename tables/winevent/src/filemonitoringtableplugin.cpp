#include "filemonitoringtableplugin.h"

#include <chrono>
#include <limits>
#include <mutex>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;

namespace zeek {

struct FileMonitoringTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status FileMonitoringTablePlugin::create(Ref &obj,
                                       IZeekConfiguration &configuration,
                                       IZeekLogger &logger) {

  try {
    obj.reset(new FileMonitoringTablePlugin(configuration, logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

FileMonitoringTablePlugin::~FileMonitoringTablePlugin() {}

const std::string &FileMonitoringTablePlugin::name() const {
  static const std::string kTableName{"file_monitoring"};

  return kTableName;
}

const FileMonitoringTablePlugin::Schema &FileMonitoringTablePlugin::schema() const {

  static const Schema kTableSchema = {
      // System fields
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

      // Event data fields
      {"subject_user_id", IVirtualTable::ColumnType::String},
      {"subject_user_name", IVirtualTable::ColumnType::String},
      {"subject_domain_name", IVirtualTable::ColumnType::String},
      {"subject_logon_id", IVirtualTable::ColumnType::String},
      {"object_server", IVirtualTable::ColumnType::String},
      {"object_type", IVirtualTable::ColumnType::String},
      {"object_name", IVirtualTable::ColumnType::String},
      {"handle_id", IVirtualTable::ColumnType::String},
      {"access_list", IVirtualTable::ColumnType::String},
      {"access_mask", IVirtualTable::ColumnType::String},
      {"process_id", IVirtualTable::ColumnType::String},
      {"process_name", IVirtualTable::ColumnType::String},
      {"resource_attributes", IVirtualTable::ColumnType::String}
  };

  return kTableSchema;
}

Status FileMonitoringTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status FileMonitoringTablePlugin::processEvents(
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
                         "file_create_events: Dropping " +
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

FileMonitoringTablePlugin::FileMonitoringTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {
  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status FileMonitoringTablePlugin::generateRow(Row &row,
                                            const WELEvent &event) {
  row = {};

  if (event.event_id != 4688) {
    return Status::success();
  }

  std::cout << "File create event: id: " << event.event_id << "\n";

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

  row["subject_user_id"] = strTree.get("EventData.SubjectUserSid", "");
  row["subject_user_name"] = strTree.get("EventData.SubjectUserName", "");
  row["subject_domain_name"] = strTree.get("EventData.SubjectDomainName", "");
  row["subject_logon_id"] = strTree.get("EventData.SubjectLogonId", "");
  row["object_server"] = strTree.get("EventData.ObjectServer", "");
  row["object_type"] = strTree.get("EventData.ObjectType", "");
  row["object_name"] = strTree.get("EventData.ObjectName", "");
  row["handle_id"] = strTree.get("EventData.HandleId", "");
  row["access_list"] = strTree.get("EventData.AccessList", "");
  row["access_mask"] = strTree.get("EventData.AccessMask", "");
  row["process_id"] = strTree.get("EventData.ProcessId", "");
  row["process_name"] = strTree.get("EventData.ProcessName", "");
  row["resource_attributes"] = strTree.get("EventData.ResourceAttributes", "");

  std::cout << "Here's event.data in file_monitoring table: " << event.data << "\n";
  std::cout << "eventdata object_type: " << strTree.get("EventData.ObjectType", "") << "\n";

  return Status::success();
}
} // namespace zeek