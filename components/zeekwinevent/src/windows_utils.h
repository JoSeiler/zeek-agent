#pragma once
#pragma warning( disable : 4267 ) //todo handle

#include <string>

namespace zeek {

/**
* @brief Windows helper function for converting narrow strings to wide
*
* @returns A wide string, constructed from a narrow string
*/
std::wstring stringToWstring(const std::string& src);

/**
 * @brief Windows helper function for converting wide strings to narrow
 *
 * @returns A narrow string, constructed from a wide string
 */
std::string wstringToString(const std::wstring& src);

/**
 * @brief Windows helper function for converting wide C-strings to narrow
 *
 * @returns A narrow string, constructed from a wide C-string
 */
std::string wstringToString(const wchar_t* src);

} // namespace zeek