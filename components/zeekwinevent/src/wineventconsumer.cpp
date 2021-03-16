#include "wineventconsumer.h"
#include "windows_utils.h"
#include "winevtlogparser.h"

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <future>
#include <iomanip>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>

namespace pt = boost::property_tree;

namespace zeek {

// Note: Windows ignores the exit code of this function
DWORD WINAPI EvtSubscriptionCallbackDispatcher(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE event) {
  auto& subscription = *static_cast<WineventConsumer*>(context);

  if (action == EvtSubscribeActionError) {
    //Todo error handling
    wprintf(L"Windows event callback error 'EvtSubscribeActionError' for channel \n");
    //LOG(ERROR)
    //    << "Windows event callback error 'EvtSubscribeActionError' for channel "
    //    << subscription.channel();

    return 0;

  } else if (action != EvtSubscribeActionDeliver) {
    //Todo error handling
    wprintf(L"Windows event callback invoked with invalid action value \n");
    //LOG(ERROR) << "Windows event callback invoked with invalid action value "
    //              "for channel "
    //           << subscription.channel();

    return 0;
  }

  wprintf(L"process events \n");
  subscription.processEvent(event);
  return 0U;
}


struct WineventConsumer::PrivateData final {
  PrivateData(IZeekLogger &logger_, IZeekConfiguration &configuration_)
      : logger(logger_), configuration(configuration_) {}

  IZeekLogger &logger;
  IZeekConfiguration &configuration;

  EVT_HANDLE handle{nullptr};
  std::string channel;

  EventList event_list;
  std::mutex event_list_mutex;
  std::condition_variable event_list_cv;
};

WineventConsumer::WineventConsumer(IZeekLogger &logger, IZeekConfiguration &configuration, const std::string &channel)
    : d(new PrivateData(logger, configuration)) {

  d->channel = channel;
  //auto channel_utf16 = stringToWstring(channel);
  LPWSTR pwsPath = L"Security";

  auto subscription = EvtSubscribe(nullptr,
                                   nullptr,
                                   pwsPath,
                                   //channel_utf16.c_str(),
                                   L"*",
                                   nullptr,
                                   this,
                                   EvtSubscriptionCallbackDispatcher,
                                   EvtSubscribeToFutureEvents);

  if (subscription == nullptr) {
    auto error = GetLastError();
    wprintf(L"Failed to subscribe to application channel \n");
    throw Status::failure("Failed to subscribe to the channel named " +
                          channel + ". Error " + std::to_string(error));
  }

  std::cout << "Subscription to Windows Event Logs successful" << "\n";
  d->handle = subscription;
}

WineventConsumer::~WineventConsumer() {
  EvtClose(d->handle);
}

const std::string WineventConsumer::channel() const {
  return d->channel;
}

Status WineventConsumer::getEvents(EventList &event_list) {
  event_list = {};

  {
    std::unique_lock<std::mutex> lock(d->event_list_mutex);

    if (d->event_list_cv.wait_for(lock, std::chrono::seconds(1U)) ==
        std::cv_status::no_timeout) {
      event_list = std::move(d->event_list);
      d->event_list = {};
    }
  }

  return Status::success();
}

Status IWineventConsumer::create(Ref &obj,
                                 IZeekLogger &logger,
                                 IZeekConfiguration &configuration,
                                 const std::string &channel) {
  obj.reset();

  try {
    obj.reset(new WineventConsumer(logger, configuration, channel));
    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

Status WineventConsumer::processEvent(EVT_HANDLE event) {
  DWORD buffer_size{0U};
  DWORD property_count{0U};

  if (!EvtRender(nullptr,
                 event,
                 EvtRenderEventXml,
                 0U,
                 nullptr,
                 &buffer_size,
                 &property_count)) {
    auto error = GetLastError();

    if (error != ERROR_INSUFFICIENT_BUFFER) {
      //LOG(ERROR) << "Failed to allocated the necessary memory to handle an "
      //              "event for channel "
      //           << d->channel;
      wprintf(L"Failed to allocated the necessary memory to handle an event \n");
      return Status::failure("Failed to allocated the necessary memory to handle an event");
    }
  }

  std::wstring buffer(buffer_size / 2U, L'\0');
  if (!EvtRender(nullptr,
                 event,
                 EvtRenderEventXml,
                 buffer_size,
                 &buffer[0],
                 &buffer_size,
                 &property_count)) {
    //auto error = GetLastError();

    //LOG(ERROR) << "Failed to process an event for channel " << d->channel
     //          << ". Error: " << error;

    wprintf(L"Failed to process an event for channel \n");
    return Status::failure("Failed to process an event for channel");
  }

  //Todo parse events
  pt::ptree propTree;
  WELEvent windows_event;
  auto xml_status = parseWindowsEventLogXML(propTree, buffer);
  if (!xml_status.succeeded() ) {
    std::cout << "Error parsing event log XML";
    return xml_status;
  }

  auto pt_status = parseWindowsEventLogPTree(windows_event, propTree);
  if (!pt_status.succeeded()) {
    std::cout << "Error parsing event log PTree";
    return pt_status;
  }
  //

  {
    std::lock_guard<std::mutex> lock(d->event_list_mutex);
    d->event_list.push_back(std::move(buffer));
  }

  d->event_list_cv.notify_one();
  return Status::success();
}

} //namespace zeek