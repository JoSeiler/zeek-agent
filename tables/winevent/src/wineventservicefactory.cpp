#include "wineventservice.h"

namespace zeek {
Status registerWineventServiceFactory(IZeekServiceManager &service_manager,
                                    IVirtualDatabase &virtual_database,
                                    IZeekConfiguration &configuration,
                                    IZeekLogger &logger) {

  WineventServiceFactory::Ref winevent_service_factory;
  auto status = WineventServiceFactory::create(
      winevent_service_factory, virtual_database, configuration, logger);

  if (!status.succeeded()) {
    return status;
  }

  status = service_manager.registerServiceFactory(std::move(winevent_service_factory));

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}
} // namespace zeek
