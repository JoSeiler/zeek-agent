#include "socketeventstableplugin.h"

#include <chrono>
#include <limits>
#include <mutex>

namespace zeek {
struct SocketEventsTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status SocketEventsTablePlugin::create(Ref &obj,
                                       IZeekConfiguration &configuration,
                                       IZeekLogger &logger) {
  try {
    auto ptr = new SocketEventsTablePlugin(configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

SocketEventsTablePlugin::~SocketEventsTablePlugin() {}

const std::string &SocketEventsTablePlugin::name() const {
  static const std::string kTableName{"socket_events"};

  return kTableName;
}

const SocketEventsTablePlugin::Schema &SocketEventsTablePlugin::schema() const {

  static const Schema kTableSchema = {
      //Todo
      { "string_column", IVirtualTable::ColumnType::String },
      { "integer_column", IVirtualTable::ColumnType::Integer },
      { "double_column", IVirtualTable::ColumnType::Double }
  };

  return kTableSchema;
}

Status SocketEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status SocketEventsTablePlugin::processEvents(
    const IWineventConsumer::EventList &event_list) {

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
                         "socket_events: Dropping " +
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

SocketEventsTablePlugin::SocketEventsTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {

  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status SocketEventsTablePlugin::generateRow(
    Row &row, const IWineventConsumer::Event &event) {
  row = {};

  //Todo

  return Status::success();
}
} // namespace zeek
