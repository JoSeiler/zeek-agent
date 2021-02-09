#pragma once

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeekconfiguration.h>
#include <zeek/izeeklogger.h>
#include <zeek/izeekservicemanager.h>
#include <zeek/status.h>

namespace zeek {
/// \brief Factory method for the WineventServiceFactory object
/// \param service_manager An initialized service manager
/// \param virtual_database The database where the Winevent tables
///                         are registered
/// \param configuration An initialized configuration object
/// \param logger An initialized logger object
Status registerWineventServiceFactory(IZeekServiceManager &service_manager,
                                    IVirtualDatabase &virtual_database,
                                    IZeekConfiguration &configuration,
                                    IZeekLogger &logger);
} // namespace zeek
