#include "accountlogontableplugin.h"

#include <chrono>
#include <limits>
#include <mutex>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;

namespace zeek {

struct AccountLogonTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status AccountLogonTablePlugin::create(Ref &obj,
                                      IZeekConfiguration &configuration,
                                      IZeekLogger &logger) {

  try {
    obj.reset(new AccountLogonTablePlugin(configuration, logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

AccountLogonTablePlugin::~AccountLogonTablePlugin() {}

const std::string &AccountLogonTablePlugin::name() const {
  static const std::string kTableName{"account_logon"};

  return kTableName;
}

const AccountLogonTablePlugin::Schema &AccountLogonTablePlugin::schema() const {

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
      {"target_user_sid", IVirtualTable::ColumnType::String},
      {"target_user_name", IVirtualTable::ColumnType::String},
      {"target_domain_name", IVirtualTable::ColumnType::String},
      {"target_logon_id", IVirtualTable::ColumnType::String},
      {"logon_type", IVirtualTable::ColumnType::Integer},
      {"logon_process_name", IVirtualTable::ColumnType::String},
      {"authentication_package_name", IVirtualTable::ColumnType::String},
      {"workstation_name", IVirtualTable::ColumnType::String},
      {"logon_guid", IVirtualTable::ColumnType::String},
      {"transmitted_services", IVirtualTable::ColumnType::String},
      {"lm_package_name", IVirtualTable::ColumnType::String},
      {"key_length", IVirtualTable::ColumnType::Integer},
      {"process_id", IVirtualTable::ColumnType::String},
      {"process_name", IVirtualTable::ColumnType::String},
      {"ip_address", IVirtualTable::ColumnType::String},
      {"ip_port", IVirtualTable::ColumnType::Integer},
      {"impersonation_level", IVirtualTable::ColumnType::String},
      {"restricted_admin_mode", IVirtualTable::ColumnType::String},
      {"target_outbound_user_name", IVirtualTable::ColumnType::String},
      {"target_outbound_domain_name", IVirtualTable::ColumnType::String},
      {"virtual_account", IVirtualTable::ColumnType::String},
      {"target_linked_logon_id", IVirtualTable::ColumnType::String},
      {"elevated_token", IVirtualTable::ColumnType::String}
  };

  return kTableSchema;
}

Status AccountLogonTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status AccountLogonTablePlugin::processEvents(
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
                         "account_logon_events: Dropping " +
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

AccountLogonTablePlugin::AccountLogonTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {
  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status AccountLogonTablePlugin::generateRow(Row &row,
                                           const WELEvent &event) {
  row = {};

  if (event.event_id != 4624) {
    return Status::success();
  }

  std::cout << "- - -" << "\n";
  std::cout << event.event_id << " - Successful account logon event" << "\n";

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

  row["subject_user_sid"] = strTree.get("EventData.SubjectUserSid", "");
  row["subject_user_name"] = strTree.get("EventData.SubjectUserName", "");
  row["subject_domain_name"] = strTree.get("EventData.SubjectDomainName", "");
  row["subject_logon_id"] = strTree.get("EventData.SubjectLogonId", "");
  row["target_user_sid"] = strTree.get("EventData.TargetUserSid", "");
  row["target_user_name"] = strTree.get("EventData.TargetUserName", "");
  row["target_domain_name"] = strTree.get("EventData.TargetDomainName", "");
  row["target_logon_id"] = strTree.get("EventData.TargetLogonId", "");
  row["logon_type"] = static_cast<std::int64_t>(strTree.get("EventData.LogonType", -1));
  row["logon_process_name"] = strTree.get("EventData.LogonProcessName", "");
  row["authentication_package_name"] = strTree.get("EventData.AuthenticationPackageName", "");
  row["workstation_name"] = strTree.get("EventData.WorkstationName", "");
  row["logon_guid"] = strTree.get("EventData.LogonGuid", "");
  row["transmitted_services"] = strTree.get("EventData.TransmittedServices", "");
  row["lm_package_name"] = strTree.get("EventData.LmPackageName", "");
  row["key_length"] = static_cast<std::int64_t>(strTree.get("EventData.KeyLength", -1));
  row["process_id"] = strTree.get("EventData.ProcessId", "");
  row["process_name"] = strTree.get("EventData.ProcessName", "");
  row["ip_address"] = strTree.get("EventData.IpAddress", "");
  row["ip_port"] = static_cast<std::int64_t>(strTree.get("EventData.IpPort", -1));
  row["impersonation_level"] = strTree.get("EventData.ImpersonationLevel", "");
  row["restricted_admin_mode"] = strTree.get("EventData.RestrictedAdminMode", "");
  row["target_outbound_user_name"] = strTree.get("EventData.TargetOutboundUserName", "");
  row["target_outbound_domain_name"] = strTree.get("EventData.TargetOutboundDomainName", "");
  row["virtual_account"] = strTree.get("EventData.VirtualAccount", "");
  row["target_linked_logon_id"] = strTree.get("EventData.TargetLinkedLogonId", "");
  row["elevated_token"] = strTree.get("EventData.ElevatedToken", "");

  std::cout << "event.data: " << event.data << "\n";
  std::cout << "- - -" << "\n";

  return Status::success();

}
} // namespace zeek