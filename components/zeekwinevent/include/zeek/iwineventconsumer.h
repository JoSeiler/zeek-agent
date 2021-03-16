#pragma once

#include <memory>
#include <variant>
#include <vector>

#include <ctime>
#include <windows.h>
#include <winevt.h>
#include <zeek/izeekconfiguration.h>
#include <zeek/izeeklogger.h>
#include <zeek/status.h>

#pragma comment(lib, "wevtapi.lib")

namespace zeek {

/// \brief WEL Event data
struct WELEvent final {
  std::time_t osquery_time{0U};
  std::string datetime;

  std::string source;
  std::string provider_name;
  std::string provider_guid;
  std::string computer_name;

  std::int64_t event_id{0U};
  std::int64_t task_id{0U};
  std::int64_t level{0U};
  std::int64_t pid{0U};
  std::int64_t tid{0U};

  std::string keywords;
  std::string data;
};

/// \brief Winevent consumer (interface)
class IWineventConsumer {
public:

  /// \brief A list of WEL events
  using EventList = std::vector<WELEvent>;

  /// \brief A unique_ptr to an IWineventConsumer
  using Ref = std::unique_ptr<IWineventConsumer>;

  /// \brief Factory method
  /// \param obj where the created object is stored
  /// \param logger an initialized logger object
  /// \param configuration an initialized configuration object
  /// \return A Status object
  static Status create(Ref &obj, IZeekLogger &logger,
                       IZeekConfiguration &configuration, const std::string &channel);

  /// \brief Constructor
  IWineventConsumer() = default;

  /// \brief Destructor
  virtual ~IWineventConsumer() = default;

  /// \brief todo
  /// \return A Status object
  virtual Status processEvent(EVT_HANDLE event) = 0;

  /// \brief Returns a list of processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  virtual Status getEvents(EventList &event_list) = 0;

  IWineventConsumer(const IWineventConsumer &other) = delete;

  IWineventConsumer &operator=(const IWineventConsumer &other) = delete;
};
} // namespace zeek


