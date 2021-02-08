#include "wineventservice.h"
#include "processeventstableplugin.h"
#include "socketeventstableplugin.h"

#include <algorithm>
#include <cassert>

#include <zeek/iwineventconsumer.h>
#include <zeek/wineventservicefactory.h>

namespace zeek {
namespace {
const std::string kServiceName{"winevent"};
} // namespace

struct WineventService::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  zeek::IWineventConsumer::Ref winevent_consumer;

  IVirtualTable::Ref process_events_table;
  IVirtualTable::Ref socket_events_table;
};

WineventService::~WineventService() {
  if (d->process_events_table) {
    auto status =
        d->virtual_database.unregisterTable(d->process_events_table->name());
    assert(status.succeeded() &&
           "Failed to unregister the process_events table");
  }
  if (d->file_events_table) {
    auto status =
        d->virtual_database.unregisterTable(d->socket_events_table->name());
    assert(status.succeeded() && "Failed to unregister the socket_events table");
  }
}

const std::string &WineventService::name() const { return kServiceName; }

Status WineventService::exec(std::atomic_bool &terminate) {
  while (!terminate) {
    if (!d->process_events_table || !d->socket_events_table) {
      d->logger.logMessage(IZeekLogger::Severity::Information,
                           "Table(s) not created yet, sleeping for 1 second");
      std::this_thread::sleep_for(std::chrono::seconds(1U));
      continue;
    }

    IWineventConsumer::EventList event_list;
    d->winevent_consumer->getEvents(event_list);

    auto &process_events_table_impl =
        *static_cast<ProcessEventsTablePlugin *>(d->process_events_table.get());

    auto &socket_events_table_impl =
        *static_cast<SocketEventsTablePlugin *>(d->socket_events_table.get());

    if (event_list.empty()) {
      continue;
    }

    auto status = process_events_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The process_events table failed to process some events: " +
          status.message());
    }

    status = socket_events_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The socket_events table failed to process some events: " +
          status.message());
    }
  }

  return Status::success();
}

WineventService::WineventService(IVirtualDatabase &virtual_database,
                             IZeekConfiguration &configuration,
                             IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {

  auto status =
      zeek::IWineventConsumer::create(d->winevent_consumer, logger, configuration);

  if (!status.succeeded()) {
    d->logger.logMessage(IZeekLogger::Severity::Error,
                         "Failed to connect to the Winevent API. The "
                         "process_events and socket_events table will not be enabled. Error: " +
                         status.message());

    return;
  }

  status = ProcessEventsTablePlugin::create(d->process_events_table,
                                            configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = SocketEventsTablePlugin::create(d->socket_events_table,
                                           configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->process_events_table);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->socket_events_table);
  if (!status.succeeded()) {
    throw status;
  }
}

struct WineventServiceFactory::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;
};

Status WineventServiceFactory::create(Ref &obj,
                                    IVirtualDatabase &virtual_database,
                                    IZeekConfiguration &configuration,
                                    IZeekLogger &logger) {
  obj.reset();

  try {
    auto ptr = new WineventServiceFactory(virtual_database, configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

WineventServiceFactory::~WineventServiceFactory() {}

const std::string &WineventServiceFactory::name() const { return kServiceName; }

Status WineventServiceFactory::spawn(IZeekService::Ref &obj) {
  obj.reset();

  try {
    obj.reset(
        new WineventService(d->virtual_database, d->configuration, d->logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

WineventServiceFactory::~WineventServiceFactory(IVirtualDatabase &virtual_database,
                                           IZeekConfiguration &configuration,
                                           IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {}
} // namespace zeek
