
#include <codecvt>
#include <wbemidl.h>
#include <string>
#include "windows_utils.h"

namespace zeek {

// Helper object used by Wide/Narrow converter functions

struct utf_converter {
  std::wstring from_bytes(const std::string& str) {
    std::wstring result;
    if (str.length() > 0) {
      result.resize(str.length() * 2);
      auto count = MultiByteToWideChar(
          CP_UTF8, 0, str.c_str(), -1, &result[0], str.length() * 2);
      result.resize(count - 1);
    }

    return result;
  }

  std::string to_bytes(const std::wstring& str) {
    std::string result;
    if (str.length() > 0) {
      result.resize(str.length() * 4);
      auto count = WideCharToMultiByte(CP_UTF8,
                                       0,
                                       str.c_str(),
                                       -1,
                                       &result[0],
                                       str.length() * 4,
                                       NULL,
                                       NULL);
      result.resize(count - 1);
    }

    return result;
  }
};

  static utf_converter converter;

  std::wstring stringToWstring(const std::string& src) {
    std::wstring utf16le_str;
    try {
    utf16le_str = converter.from_bytes(src);
    } catch (std::exception /* e */) {
        //LOG(WARNING) << "Failed to convert string to wstring " << src;
    }

    return utf16le_str;
  }

  std::string wstringToString(const std::wstring& src) {
    std::string utf8_str = converter.to_bytes(src);
    return utf8_str;
  }

} // namespace zeek