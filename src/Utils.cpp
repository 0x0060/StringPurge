#include "Utils.h"
#include "Logger.h"
#include <windows.h>

namespace utils {

    std::wstring stringToWString(const std::string& str) {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wstr[0], size_needed);
        return wstr;
    }

    std::string wstringToString(const std::wstring& wstr) {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], size_needed, NULL, NULL);
        return str;
    }

    void printError(const std::string& context) {
        Logger::log(LogLevel::ERROR, context + " Error code: " + std::to_string(GetLastError()));
    }

    void handleError(const std::string& context) {
        printError(context);
        throw std::runtime_error(context + " failed.");
    }
}
