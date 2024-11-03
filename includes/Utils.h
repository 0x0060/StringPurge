#ifndef UTILS_H
#define UTILS_H

#include <string>

namespace utils {

    std::wstring stringToWString(const std::string& str);
    std::string wstringToString(const std::wstring& wstr);
    void printError(const std::string& context);
    void handleError(const std::string& context);

}

#endif
