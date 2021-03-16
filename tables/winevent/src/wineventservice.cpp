#include "wineventservice.h"
#include "socketeventstableplugin.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <thread>

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

  IWineventConsumer::Ref winevent_consumer;

  IVirtualTable::Ref socket_events_table;
};

WineventService::~WineventService() {
  if (d->socket_events_table) {
    auto status =
        d->virtual_database.unregisterTable(d->socket_events_table->name());
    assert(status.succeeded() &&
           "Failed to unregister the socket_events table");
  }
}

const std::string &WineventService::name() const { return kServiceName; }

Status WineventService::exec(std::atomic_bool &terminate) {

  while (!terminate) {

    if (!d->socket_events_table) {
      d->logger.logMessage(IZeekLogger::Severity::Information,
                           "Table(s) not created yet, sleeping for 1 second");
      std::this_thread::sleep_for(std::chrono::seconds(1U));
      continue;
    }

    auto &socket_events_table_impl =
        *static_cast<SocketEventsTablePlugin *>(d->socket_events_table.get());

    IWineventConsumer::EventList event_list;
    d->winevent_consumer->getEvents(event_list);

    if (event_list.empty()) {
      continue;
    }

    auto status = socket_events_table_impl.processEvents(event_list);
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

  std::string channel = "makethisselectable"; //todo

  auto status =
      IWineventConsumer::create(d->winevent_consumer, logger, configuration, channel);

  if (!status.succeeded()) {
    d->logger.logMessage(IZeekLogger::Severity::Error,
                         "Failed to connect to the WEL API. The "
                         "socket_events tables will not be enabled. Error: " +
                         status.message());

    return;
  }

  status = SocketEventsTablePlugin::create(d->socket_events_table,
                                           configuration, logger);
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
    auto ptr =
        new WineventServiceFactory(virtual_database, configuration, logger);
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

WineventServiceFactory::WineventServiceFactory(IVirtualDatabase &virtual_database,
                                             IZeekConfiguration &configuration,
                                             IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {}

} // namespace zeek