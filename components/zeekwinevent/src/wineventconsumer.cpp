#include "wineventconsumer.h"

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <future>
#include <iomanip>

namespace zeek {
struct WineventConsumer::PrivateData final {
  PrivateData(IZeekLogger &logger_, IZeekConfiguration &configuration_)
      : logger(logger_), configuration(configuration_) {}

  IZeekLogger &logger;
  IZeekConfiguration &configuration;

  EventList event_list;
  std::mutex event_list_mutex;
  std::condition_variable event_list_cv;

  //std::atomic_bool terminate_producer{false};
};

WineventConsumer::~WineventConsumer() {

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

Status IWineventConsumer::create(Ref &obj, IZeekLogger &logger,
                                IZeekConfiguration &configuration) {
  try {
    obj.reset(new WineventConsumer(logger, configuration));
    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

} //namespace zeek