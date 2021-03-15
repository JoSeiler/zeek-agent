#pragma once

#include <memory>
#include <variant>
#include <vector>

#include <zeek/izeekconfiguration.h>
#include <zeek/izeeklogger.h>
#include <zeek/status.h>
#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

namespace zeek {
/// \brief Winevent consumer (interface)
class IWineventConsumer {
public:
  /// \brief WEL Event data
  struct WELEvent final {
    //Todo define WELevent structure
    /// \brief test
    std::string provider_name;
    std::int64_t event_id{0u};
    std::int64_t version{0u};
    std::int64_t level{0u};
    std::int64_t task{0u};
    std::int64_t opcode{0u};
    std::string keywords;
    std::string time_created;
    std::int64_t event_record_id{0u};
    std::int64_t process_id{0u};
    std::int64_t threat_id {0u};

    std::string data;


    std::string test;
  };

  /// \brief A list of WEL events
  using Event = std::wstring;
  using EventList = std::vector<Event>;
  //using EventList = std::vector<WELEvent>;

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


