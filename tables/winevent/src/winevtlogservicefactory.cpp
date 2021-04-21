#include "winevtlogservice.h"

namespace zeek {
Status registerWinevtlogServiceFactory(IZeekServiceManager &service_manager,
                                    IVirtualDatabase &virtual_database,
                                    IZeekConfiguration &configuration,
                                    IZeekLogger &logger) {

  WinevtlogServiceFactory::Ref winevtlog_service_factory;
  auto status = WinevtlogServiceFactory::create(
      winevtlog_service_factory, virtual_database, configuration, logger);

  if (!status.succeeded()) {
    return status;
  }

  status = service_manager.registerServiceFactory(std::move(winevtlog_service_factory));

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}
} // namespace zeek
