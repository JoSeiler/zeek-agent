#include "regvalmodifiedtableplugin.h"

#include <chrono>
#include <limits>
#include <mutex>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;

namespace zeek {

struct RegValModifiedTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status RegValModifiedTablePlugin::create(Ref &obj,
                                       IZeekConfiguration &configuration,
                                       IZeekLogger &logger) {

  try {
    obj.reset(new RegValModifiedTablePlugin(configuration, logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

RegValModifiedTablePlugin::~RegValModifiedTablePlugin() {}

const std::string &RegValModifiedTablePlugin::name() const {
  static const std::string kTableName{"regval_modified"};

  return kTableName;
}

const RegValModifiedTablePlugin::Schema &RegValModifiedTablePlugin::schema() const {

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
      {"object_name", IVirtualTable::ColumnType::String},
      {"object_value_name", IVirtualTable::ColumnType::String},
      {"handle_id", IVirtualTable::ColumnType::String},
      {"operation_type", IVirtualTable::ColumnType::String},
      {"old_value_type", IVirtualTable::ColumnType::String},
      {"old_value", IVirtualTable::ColumnType::String},
      {"new_value_type", IVirtualTable::ColumnType::String},
      {"new_value", IVirtualTable::ColumnType::String},
      {"process_id", IVirtualTable::ColumnType::String},
      {"process_name", IVirtualTable::ColumnType::String},
  };

  return kTableSchema;
}

Status RegValModifiedTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status RegValModifiedTablePlugin::processEvents(
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
                         "regval_modified_events: Dropping " +
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

RegValModifiedTablePlugin::RegValModifiedTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {
  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status RegValModifiedTablePlugin::generateRow(Row &row,
                                            const WELEvent &event) {

  row = {};

  if (event.event_id != 4657)
  {
    return Status::success();
  }

  std::cout << "- - -" << "\n";
  std::cout << event.event_id << " - Registry value modification event" << "\n";

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
  row["object_name"] = strTree.get("EventData.ObjectName", "");
  row["object_value_name"] = strTree.get("EventData.ObjectValueName", "");
  row["handle_id"] = strTree.get("EventData.HandleId", "");
  row["operation_type"] = strTree.get("EventData.OperationType", "");
  row["old_value_type"] = strTree.get("EventData.OldValueType", "");
  row["old_value"] = strTree.get("EventData.OldValue", "");
  row["new_value_type"] = strTree.get("EventData.NewValueType", "");
  row["new_value"] = strTree.get("EventData.NewValue", "");
  row["process_id"] = strTree.get("EventData.ProcessId", "");
  row["process_name"] = strTree.get("EventData.ProcessName", "");

  std::cout << "event.data: " << event.data << "\n";
  std::cout << "- - -" << "\n";

  return Status::success();
}
} // namespace zeek