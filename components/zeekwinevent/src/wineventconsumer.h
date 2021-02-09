#pragma once

#include <memory>
#include <optional>
#include <vector>

#include <zeek/iwindowseventconsumer.h>

namespace zeek {
class WineventConsumer final : public IWineventConsumer {
public:
  /// \brief Destructor
  ~WineventConsumer() override;

  /// \brief Returns a list of processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  Status getEvents(EventList &event_list) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// \brief Constructor
  WineventConsumer(IZeekLogger &logger, IZeekConfiguration &configuration);



public:
  friend class IWineventConsumer;

};
} // namespace zeek