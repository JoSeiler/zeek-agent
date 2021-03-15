#pragma once
#pragma warning( disable : 4267 ) //todo handle

#include <string>

namespace zeek {

  /// \brief Windows helper function for coverting narrow strings to wirde
  /// \param src source string
  /// \return output a wide string, constructed from a narrow string
  std::wstring stringToWstring(const std::string &src);

  /**
  * @brief Windows helper function for converting wide C-strings to narrow
  *
  * @returns A narrow string, constructed from a wide C-string
  */
  std::string wstringToString(const wchar_t* src);

} // namespace zeek