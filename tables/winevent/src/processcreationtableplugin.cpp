#include "processcreationtableplugin.h"

#include <chrono>
#include <limits>
#include <mutex>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;

namespace zeek {

struct ProcessCreationTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status ProcessCreationTablePlugin::create(Ref &obj,
                                       IZeekConfiguration &configuration,
                                       IZeekLogger &logger) {

  try {
    obj.reset(new ProcessCreationTablePlugin(configuration, logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ProcessCreationTablePlugin::~ProcessCreationTablePlugin() {}

const std::string &ProcessCreationTablePlugin::name() const {
  static const std::string kTableName{"process_creation"};

  return kTableName;
}

const ProcessCreationTablePlugin::Schema &ProcessCreationTablePlugin::schema() const {

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
      {"data", IVirtualTable::ColumnType::String},

      // Event data
      {"subject_user_id", IVirtualTable::ColumnType::String},
      {"subject_user_name", IVirtualTable::ColumnType::String},
      {"subject_domain_name", IVirtualTable::ColumnType::String},
      {"subject_logon_id", IVirtualTable::ColumnType::String},
      {"new_process_id", IVirtualTable::ColumnType::String},
      {"new_process_name", IVirtualTable::ColumnType::String},
      {"token_elevation_type", IVirtualTable::ColumnType::String},
      {"process_id", IVirtualTable::ColumnType::String},
      {"command_line", IVirtualTable::ColumnType::String},
      {"target_user_sid", IVirtualTable::ColumnType::String},
      {"target_user_name", IVirtualTable::ColumnType::String},
      {"target_logon_id", IVirtualTable::ColumnType::String},
      {"target_domain_name", IVirtualTable::ColumnType::String},
      {"parent_process_name", IVirtualTable::ColumnType::String},
      {"mandatory_label", IVirtualTable::ColumnType::String}
  };

  return kTableSchema;
}

Status ProcessCreationTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status ProcessCreationTablePlugin::processEvents(
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
                         "process_creation_events: Dropping " +
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

ProcessCreationTablePlugin::ProcessCreationTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {
  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status ProcessCreationTablePlugin::generateRow(Row &row,
                                            const WELEvent &event) {
  row = {};

  if (event.event_id != 4688) {
    return Status::success();
  }

  std::cout << "- - -" << "\n";
  std::cout << event.event_id << " - Process creation event" << "\n";

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
  row["new_process_id"] = strTree.get("EventData.NewProcessId", "");
  row["new_process_name"] = strTree.get("EventData.NewProcessName", "");
  row["token_elevation_type"] = strTree.get("EventData.TokenElevationType", "");
  row["process_id"] = strTree.get("EventData.ProcessId", "");
  row["command_line"] = strTree.get("EventData.CommandLine", "");
  row["target_user_sid"] = strTree.get("EventData.TargetUserSid", "");
  row["target_user_name"] = strTree.get("EventData.TargetUserName", "");
  row["target_domain_name"] = strTree.get("EventData.TargetDomainName", "");
  row["target_logon_id"] = strTree.get("EventData.TargetLogonId", "");
  row["parent_process_name"] = strTree.get("EventData.ParentProcessName", "");
  row["mandatory_label"] = strTree.get("EventData.MandatoryLabel", "");

  std::cout << "event.data: " << event.data << "\n";
  std::cout << "- - -" << "\n";

  return Status::success();
}
} // namespace zeek