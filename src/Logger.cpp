#include "Logger.h"

void Logger::log(LogLevel level, const std::string& message) {
    std::cout << "(" << logLevelToString(level) << "): " << getCurrentTime() << " - " << message << std::endl;
}

std::string Logger::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string Logger::logLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::INFO:    return "INF";
        case LogLevel::ERROR:   return "ERR";
        case LogLevel::DEBUG:   return "DBG";
        case LogLevel::SYSTEM:  return "SYS";
        case LogLevel::MEMORY:  return "MEM";
        default:                return "UNK";
    }
}
