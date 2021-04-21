#include "winevtlogservice.h"
#include "networkconntableplugin.h"
#include "processcreationtableplugin.h"
#include "processterminationtableplugin.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <thread>

#include <zeek/iwineventconsumer.h>
#include <zeek/winevtlogservicefactory.h>

namespace zeek {
namespace {
const std::string kServiceName{"winevtlog"};
} // namespace

struct WinevtlogService::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  IWineventConsumer::Ref winevent_consumer;

  IVirtualTable::Ref network_conn_table;
  IVirtualTable::Ref process_creation_table;
  IVirtualTable::Ref process_termination_table;
};

WinevtlogService::~WinevtlogService() {
  if (d->network_conn_table) {
    auto status =
        d->virtual_database.unregisterTable(d->network_conn_table->name());
    assert(status.succeeded() &&
           "Failed to unregister the network_conn table");
  }

  if (d->process_creation_table) {
    auto status =
        d->virtual_database.unregisterTable(d->process_creation_table->name());
    assert(status.succeeded() &&
           "Failed to unregister the process_creation table");
  }

  if (d->process_termination_table) {
    auto status =
        d->virtual_database.unregisterTable(d->process_termination_table->name());
    assert(status.succeeded() &&
           "Failed to unregister the process_termination table");
  }
}

const std::string &WinevtlogService::name() const { return kServiceName; }

Status WinevtlogService::exec(std::atomic_bool &terminate) {

  while (!terminate) {

    if (!d->network_conn_table || !d->process_creation_table || !d->process_termination_table) {
      d->logger.logMessage(IZeekLogger::Severity::Information,
                           "Table(s) not created yet, sleeping for 1 second");
      std::this_thread::sleep_for(std::chrono::seconds(1U));
      continue;
    }

    auto &network_conn_table_impl =
        *static_cast<NetworkConnTablePlugin *>(d->network_conn_table.get());

    auto &process_creation_table_impl =
        *static_cast<ProcessCreationTablePlugin *>(d->process_creation_table.get());

    auto &process_termination_table_impl =
        *static_cast<ProcessTerminationTablePlugin *>(d->process_termination_table.get());

    IWineventConsumer::EventList event_list;
    d->winevent_consumer->getEvents(event_list);

    if (event_list.empty()) {
      continue;
    }

    auto status = network_conn_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The socket_events table failed to process some events: " +
          status.message());
    }

    status = process_creation_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The process_creation table failed to process some events: " +
          status.message());
    }

    status = process_termination_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The process_termination table failed to process some events: " +
          status.message());
    }
  }

  return Status::success();
}

WinevtlogService::WinevtlogService(IVirtualDatabase &virtual_database,
                               IZeekConfiguration &configuration,
                               IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {

  std::string channel = "makethisselectable"; //todo

  auto status =
      IWineventConsumer::create(d->winevent_consumer, logger, configuration, channel);

  if (!status.succeeded()) {
    d->logger.logMessage(IZeekLogger::Severity::Error,
                         "Failed to connect to the WEL API. The "
                         "WEL tables will not be enabled. Error: " +
                         status.message());

    return;
  }

  status = NetworkConnTablePlugin::create(d->network_conn_table,
                                           configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->network_conn_table);
  if (!status.succeeded()) {
    throw status;
  }

  status = ProcessCreationTablePlugin::create(d->process_creation_table,
                                           configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->process_creation_table);
  if (!status.succeeded()) {
    throw status;
  }

  status = ProcessTerminationTablePlugin::create(d->process_termination_table,
                                              configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->process_termination_table);
  if (!status.succeeded()) {
    throw status;
  }
}

struct WinevtlogServiceFactory::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;
};

Status WinevtlogServiceFactory::create(Ref &obj,
                                     IVirtualDatabase &virtual_database,
                                     IZeekConfiguration &configuration,
                                     IZeekLogger &logger) {
  obj.reset();

  try {
    auto ptr =
        new WinevtlogServiceFactory(virtual_database, configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

WinevtlogServiceFactory::~WinevtlogServiceFactory() {}

const std::string &WinevtlogServiceFactory::name() const { return kServiceName; }

Status WinevtlogServiceFactory::spawn(IZeekService::Ref &obj) {
  obj.reset();

  try {
    obj.reset(
        new WinevtlogService(d->virtual_database, d->configuration, d->logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

WinevtlogServiceFactory::WinevtlogServiceFactory(IVirtualDatabase &virtual_database,
                                             IZeekConfiguration &configuration,
                                             IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {}

} // namespace zeek