#pragma once

#include <memory>
#include <optional>
#include <vector>

#include <zeek/iwinevtlogconsumer.h>
#include <zeek/status.h>

namespace zeek {

DWORD WINAPI EvtSubscriptionCallbackDispatcher(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE event);

class WinevtlogConsumer final : public IWinevtlogConsumer {
public:
  /// \brief Destructor
  ~WinevtlogConsumer() override;

  //Todo brief
  const std::string channel() const;

  /// \brief Returns a list of processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  Status getEvents(EventList &event_list) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// \brief Constructor
  WinevtlogConsumer(IZeekLogger &logger, IZeekConfiguration &configuration, const std::string &channel);

  /// \brief Process WEL and generate object
  virtual Status processEvent(EVT_HANDLE event) override;

  friend DWORD WINAPI EvtSubscriptionCallbackDispatcher(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE event);

public:
  friend class IWinevtlogConsumer;

};
} // namespace zeek